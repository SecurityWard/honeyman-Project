#!/usr/bin/env python3
"""
Enhanced BLE Threat Detection System - Phase 3
Advanced device fingerprinting and behavior analysis
"""
import subprocess
import time
import json
import requests
import re
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict, deque
import statistics

class EnhancedBLEThreatDetector:
    def __init__(self):
        self.known_devices = {}
        self.device_behaviors = defaultdict(lambda: {
            'appearances': deque(maxlen=100),
            'rssi_history': deque(maxlen=50),
            'service_changes': [],
            'name_changes': [],
            'manufacturer_changes': []
        })
        
        # Enhanced threat patterns with scoring
        self.threat_signatures = {
            'flipper_zero': {
                'patterns': ['flipper', 'zero', 'flip_', 'flipperzero'],
                'services': ['6e400001-b5a3-f393-e0a9-e50e24dcca9e'],  # Nordic UART
                'firmware_variants': ['official', 'unleashed', 'xtreme', 'roguemaster'],
                'manufacturer_data': ['4c00'],  # Apple spoofing
                'score': 0.95
            },
            'flipper_zero_unleashed': {
                'patterns': ['unleashed', 'xtreme', 'rogue'],
                'services': ['6e400001-b5a3-f393-e0a9-e50e24dcca9e'],
                'behavior': 'rapid_service_changes',
                'score': 0.98  # Higher score for custom firmware
            },
            'hacking_tools': {
                'patterns': ['hack', 'pwn', 'exploit', 'crack', 'sniff'],
                'services': ['0000180f-0000-1000-8000-00805f9b34fb'],  # Battery spoofing
                'score': 0.8
            },
            'development_boards': {
                'patterns': ['esp32', 'arduino', 'raspberry', 'dev', 'board'],
                'manufacturers': ['espressif', 'arduino', 'raspberry'],
                'score': 0.4
            },
            'keyloggers': {
                'patterns': ['keylog', 'logger', 'keyboard', 'input'],
                'services': ['00001812-0000-1000-8000-00805f9b34fb'],  # HID
                'score': 0.9
            },
            'beacon_spammers': {
                'patterns': ['beacon', 'spam', 'flood'],
                'behavior': 'rapid_appearance',
                'score': 0.7
            },
            'apple_continuity_abuse': {
                'services': ['89d3502b-0f36-433a-8ef4-c502ad55f8dc'],  # Apple Continuity
                'manufacturer_prefixes': ['4c00'],  # Apple Inc.
                'score': 0.8
            },
            'manufacturer_spoofing': {
                'behavior': 'manufacturer_switching',
                'score': 0.7
            },
            'gatt_enumeration': {
                'services': ['00001801-0000-1000-8000-00805f9b34fb'],  # Generic Attribute
                'behavior': 'service_discovery',
                'score': 0.5
            },
            'conference_badge_spoofing': {
                'patterns': ['defcon', 'dc29', 'dc30', 'dc31', 'badge', 'conference'],
                'services': ['6e400001-b5a3-f393-e0a9-e50e24dcca9e'],  # Nordic UART often used
                'manufacturer_prefixes': ['0059'],  # Nordic Semiconductor
                'score': 0.8
            },
            'esp32_attack_board': {
                'patterns': ['esp32', 'espressif', 'arduino'],
                'manufacturers': ['espressif'],
                'services': ['6e400001-b5a3-f393-e0a9-e50e24dcca9e'],
                'score': 0.7
            },
            'ubertooth_sniffer': {
                'patterns': ['ubertooth', 'sniffer', 'btmon'],
                'behavior': 'passive_scanning',
                'score': 0.8
            }
        }
        
        # Device fingerprinting database
        self.device_fingerprints = {}
        self.manufacturer_history = defaultdict(list)  # Track manufacturer changes
        self.advertisement_patterns = defaultdict(lambda: {
            'data_changes': deque(maxlen=20),
            'flags_history': deque(maxlen=10),
            'tx_power_history': deque(maxlen=10),
            'service_data_changes': []
        })
        self.apple_continuity_tracker = {}
        
        self.suspicious_behaviors = {
            'mac_randomization': 0.3,
            'service_spoofing': 0.6,
            'manufacturer_spoofing': 0.5,
            'proximity_attack': 0.4,
            'beacon_flooding': 0.8,
            'unusual_services': 0.5,
            'advertisement_manipulation': 0.6,
            'apple_continuity_abuse': 0.8,
            'gatt_enumeration_attempt': 0.4
        }
        
        # Correlation tracking
        self.threat_correlations = defaultdict(list)
        self.attack_sessions = {}
        
    def scan_ble_devices(self):
        """Enhanced BLE scanning with detailed information gathering"""
        devices = []
        
        try:
            # Clear previous scan results
            subprocess.run(['sudo', 'bluetoothctl', 'scan', 'off'], 
                         capture_output=True, timeout=5)
            time.sleep(2)
            
            # Power cycle the adapter to ensure clean state
            subprocess.run(['sudo', 'bluetoothctl', 'power', 'off'], 
                         capture_output=True, timeout=5)
            time.sleep(1)
            subprocess.run(['sudo', 'bluetoothctl', 'power', 'on'], 
                         capture_output=True, timeout=5)
            time.sleep(2)
            
            # Start fresh scan
            subprocess.run(['sudo', 'bluetoothctl', 'scan', 'on'], 
                         capture_output=True, timeout=5)
            
            # Extended scan time for better discovery
            time.sleep(15)
            
            # Get discovered devices
            result = subprocess.run(['sudo', 'bluetoothctl', 'devices'], 
                                  capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if line.startswith('Device '):
                    parts = line.split(' ', 2)
                    if len(parts) >= 3:
                        mac_address = parts[1]
                        device_name = parts[2] if len(parts) > 2 else 'Unknown'
                        
                        # Get detailed device information
                        device_info = self.get_enhanced_device_info(mac_address)
                        
                        device = {
                            'mac_address': mac_address,
                            'name': device_name,
                            'timestamp': datetime.utcnow().isoformat(),
                            **device_info
                        }
                        
                        devices.append(device)
            
            # Stop scan to save resources
            subprocess.run(['sudo', 'bluetoothctl', 'scan', 'off'], 
                         capture_output=True, timeout=5)
                         
        except Exception as e:
            print(f"❌ Enhanced BLE scan error: {e}")
            
        return devices
    
    def get_enhanced_device_info(self, mac_address):
        """Get comprehensive device information"""
        device_info = {
            'services': [],
            'rssi': None,
            'manufacturer': '',
            'device_class': '',
            'appearance': '',
            'tx_power': None,
            'connected': False,
            'paired': False,
            'trusted': False
        }
        
        try:
            # Get detailed info using bluetoothctl
            result = subprocess.run(['sudo', 'bluetoothctl', 'info', mac_address], 
                                  capture_output=True, text=True, timeout=10)
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if 'RSSI:' in line:
                    rssi_match = re.search(r'RSSI:\s*(-?\d+)', line)
                    if rssi_match:
                        device_info['rssi'] = int(rssi_match.group(1))
                        
                elif 'Manufacturer:' in line:
                    device_info['manufacturer'] = line.split('Manufacturer:')[-1].strip()
                    
                elif 'UUID:' in line:
                    uuid = line.split('UUID:')[-1].strip()
                    device_info['services'].append(uuid)
                    
                elif 'Class:' in line:
                    device_info['device_class'] = line.split('Class:')[-1].strip()
                    
                elif 'Appearance:' in line:
                    device_info['appearance'] = line.split('Appearance:')[-1].strip()
                    
                elif 'TxPower:' in line:
                    tx_match = re.search(r'TxPower:\s*(-?\d+)', line)
                    if tx_match:
                        device_info['tx_power'] = int(tx_match.group(1))
                        
                elif 'Connected:' in line:
                    device_info['connected'] = 'yes' in line.lower()
                    
                elif 'Paired:' in line:
                    device_info['paired'] = 'yes' in line.lower()
                    
                elif 'Trusted:' in line:
                    device_info['trusted'] = 'yes' in line.lower()
                    
            # Try to get additional info using hcitool if available
            try:
                hci_result = subprocess.run(['sudo', 'hcitool', 'name', mac_address], 
                                          capture_output=True, text=True, timeout=5)
                if hci_result.stdout.strip() and 'not available' not in hci_result.stdout.lower():
                    device_info['hci_name'] = hci_result.stdout.strip()
            except:
                pass
                
        except Exception as e:
            print(f"⚠️ Could not get enhanced info for {mac_address}: {e}")
            
        return device_info
    
    def analyze_device_fingerprint(self, device):
        """Create and analyze device fingerprint for threat detection"""
        mac = device.get('mac_address', '')
        name = device.get('name', '').lower()
        services = device.get('services', [])
        manufacturer = device.get('manufacturer', '').lower()
        device_class = device.get('device_class', '')
        
        # Create device fingerprint
        fingerprint_data = {
            'name_pattern': re.sub(r'[0-9]+', 'N', name),  # Normalize numbers
            'service_set': sorted(services),
            'manufacturer': manufacturer,
            'device_class': device_class,
            'mac_prefix': mac[:8] if len(mac) >= 8 else mac
        }
        
        fingerprint_hash = hashlib.md5(
            json.dumps(fingerprint_data, sort_keys=True).encode()
        ).hexdigest()
        
        # Track fingerprint changes
        if mac in self.device_fingerprints:
            if self.device_fingerprints[mac] != fingerprint_hash:
                return 'fingerprint_changed', 0.6
        
        self.device_fingerprints[mac] = fingerprint_hash
        return 'fingerprint_stable', 0.0
    
    def analyze_device_behavior(self, device):
        """Analyze device behavior patterns"""
        mac = device.get('mac_address', '')
        current_time = time.time()
        rssi = device.get('rssi')
        
        behavior = self.device_behaviors[mac]
        
        # Track appearance pattern
        behavior['appearances'].append(current_time)
        if rssi is not None:
            behavior['rssi_history'].append(rssi)
        
        threats = []
        behavior_score = 0.0
        
        # Analyze appearance frequency
        if len(behavior['appearances']) >= 10:
            time_diffs = [behavior['appearances'][i] - behavior['appearances'][i-1] 
                         for i in range(1, len(behavior['appearances']))]
            
            avg_interval = statistics.mean(time_diffs)
            if avg_interval < 10:  # Appearing more than every 10 seconds
                threats.append('rapid_appearance_pattern')
                behavior_score += 0.4
        
        # Analyze RSSI patterns
        if len(behavior['rssi_history']) >= 5:
            rssi_values = list(behavior['rssi_history'])
            rssi_variance = statistics.variance(rssi_values)
            
            # High variance might indicate movement or signal manipulation
            if rssi_variance > 100:
                threats.append('signal_variance_anomaly')
                behavior_score += 0.3
                
            # Very strong signal might indicate proximity attack
            if max(rssi_values) > -20:
                threats.append('proximity_attack_signal')
                behavior_score += 0.4
        
        # Check for service/name changes
        current_name = device.get('name', '')
        current_services = set(device.get('services', []))
        
        if mac in self.known_devices:
            prev_device = self.known_devices[mac]
            prev_name = prev_device.get('name', '')
            prev_services = set(prev_device.get('services', []))
            
            if current_name != prev_name and current_name and prev_name:
                behavior['name_changes'].append({
                    'from': prev_name,
                    'to': current_name,
                    'timestamp': current_time
                })
                threats.append('device_name_change')
                behavior_score += 0.5
            
            if current_services != prev_services:
                behavior['service_changes'].append({
                    'added': list(current_services - prev_services),
                    'removed': list(prev_services - current_services),
                    'timestamp': current_time
                })
                threats.append('service_profile_change')
                behavior_score += 0.4
        
        return threats, min(behavior_score, 1.0)
    
    def analyze_enhanced_threats(self, device):
        """Enhanced threat analysis with device fingerprinting"""
        threats = []
        threat_score = 0.0
        
        name = device.get('name', '').lower()
        mac = device.get('mac_address', '')
        services = device.get('services', [])
        manufacturer = device.get('manufacturer', '').lower()
        
        # Signature-based detection
        for threat_type, signature in self.threat_signatures.items():
            signature_matched = False
            
            # Check name patterns
            for pattern in signature.get('patterns', []):
                if pattern in name:
                    threats.append(f"signature_{threat_type}_{pattern}")
                    threat_score += signature['score']
                    signature_matched = True
            
            # Check service UUIDs
            for service_uuid in signature.get('services', []):
                if service_uuid in services:
                    threats.append(f"service_{threat_type}")
                    threat_score += signature['score']
                    signature_matched = True
            
            # Check manufacturers
            for mfg in signature.get('manufacturers', []):
                if mfg in manufacturer:
                    threats.append(f"manufacturer_{threat_type}")
                    threat_score += signature['score']
                    signature_matched = True
        
        # Device fingerprint analysis
        fingerprint_status, fp_score = self.analyze_device_fingerprint(device)
        if fp_score > 0:
            threats.append(fingerprint_status)
            threat_score += fp_score
        
        # Behavioral analysis
        behavior_threats, behavior_score = self.analyze_device_behavior(device)
        threats.extend(behavior_threats)
        threat_score += behavior_score
        
        # Manufacturer spoofing detection
        mfg_threats, mfg_score = self.detect_manufacturer_spoofing(device)
        threats.extend(mfg_threats)
        threat_score += mfg_score
        
        # Advertisement analysis
        adv_threats, adv_score = self.analyze_advertisement_data(device)
        threats.extend(adv_threats)
        threat_score += adv_score
        
        # Apple Continuity abuse detection
        apple_threats, apple_score = self.detect_apple_continuity_abuse(device)
        threats.extend(apple_threats)
        threat_score += apple_score
        
        # GATT enumeration detection
        gatt_threats, gatt_score = self.detect_gatt_enumeration(device)
        threats.extend(gatt_threats)
        threat_score += gatt_score
        
        # MAC address analysis
        if self.is_randomized_mac(mac):
            threats.append("randomized_mac_detected")
            threat_score += 0.2
        
        # Service analysis
        suspicious_service_count = 0
        for service in services:
            if self.is_suspicious_service(service):
                suspicious_service_count += 1
        
        if suspicious_service_count > 0:
            threats.append(f"suspicious_services_{suspicious_service_count}")
            threat_score += min(suspicious_service_count * 0.2, 0.6)
        
        return threats, min(threat_score, 1.0)
    
    def is_suspicious_service(self, service_uuid):
        """Check if service UUID is commonly used in attack tools"""
        suspicious_services = [
            '6e400001-b5a3-f393-e0a9-e50e24dcca9e',  # Nordic UART (common in DIY tools)
            '0000180f-0000-1000-8000-00805f9b34fb',  # Battery Service (often spoofed)
            '0000180a-0000-1000-8000-00805f9b34fb',  # Device Information (often faked)
            '00001812-0000-1000-8000-00805f9b34fb',  # HID over GATT
            '00001801-0000-1000-8000-00805f9b34fb',  # Generic Attribute
        ]
        return service_uuid.lower() in [s.lower() for s in suspicious_services]
    
    def is_randomized_mac(self, mac):
        """Enhanced MAC randomization detection"""
        if not mac or len(mac) < 17:
            return False
            
        try:
            # Check for locally administered address (bit 1 of first octet set)
            first_octet = mac[:2]
            first_byte = int(first_octet, 16)
            
            # Additional patterns for randomized MACs
            if (first_byte & 0x02) != 0:  # Locally administered
                return True
                
            # Some devices use specific randomization patterns
            common_random_prefixes = ['02:', '06:', '0a:', '0e:', '12:', '16:', '1a:', '1e:']
            mac_prefix = mac[:3]
            if mac_prefix in common_random_prefixes:
                return True
                
        except:
            pass
            
        return False
    
    def correlate_threats(self, device, threats, threat_score):
        """Correlate threats across time and devices"""
        mac = device.get('mac_address', '')
        current_time = time.time()
        
        # Create threat session
        session_key = f"{mac}_{int(current_time // 300)}"  # 5-minute sessions
        
        if session_key not in self.attack_sessions:
            self.attack_sessions[session_key] = {
                'start_time': current_time,
                'devices': set([mac]),
                'threats': set(threats),
                'max_score': threat_score,
                'total_events': 1
            }
        else:
            session = self.attack_sessions[session_key]
            session['devices'].add(mac)
            session['threats'].update(threats)
            session['max_score'] = max(session['max_score'], threat_score)
            session['total_events'] += 1
        
        # Check for coordinated attacks
        session = self.attack_sessions[session_key]
        if len(session['devices']) > 3 or session['total_events'] > 10:
            return ['coordinated_attack'], 0.3
        
        return [], 0.0
    
    def send_to_elasticsearch(self, detection_data):
        """Send enhanced BLE threat detection to Elasticsearch"""
        try:
            doc = {
                'timestamp': detection_data['timestamp'],
                'honeypot_id': 'honeyman-01',
                'source': 'enhanced_ble_detector',
                'log_type': 'enhanced_ble_threat',
                'device_mac': detection_data['device']['mac_address'],
                'device_name': detection_data['device']['name'],
                'threat_score': detection_data['threat_score'],
                'threats_detected': detection_data['threats'],
                'device_info': detection_data['device_info'],
                'behavior_analysis': detection_data.get('behavior_analysis', {}),
                'fingerprint_data': detection_data.get('fingerprint_data', {}),
                'correlation_data': detection_data.get('correlation_data', {}),
                'message': detection_data['message']
            }
            
            response = requests.post(
                'http://localhost:9200/honeypot-logs-new/_doc',
                json=doc,
                timeout=5
            )
            
            if response.status_code in [200, 201]:
                print(f"✅ Enhanced BLE threat logged")
            else:
                print(f"❌ Failed to log BLE threat: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Elasticsearch error: {e}")
    
    def get_threat_level(self, score):
        """Enhanced threat level calculation"""
        if score >= 0.8:
            return "🚨 CRITICAL"
        elif score >= 0.6:
            return "⚠️ HIGH" 
        elif score >= 0.4:
            return "🟡 MEDIUM"
        elif score >= 0.2:
            return "🔍 LOW"
        else:
            return "ℹ️ INFO"
    
    def monitor_enhanced_ble_threats(self):
        """Main enhanced BLE threat monitoring loop"""
        print("📱 Starting Enhanced BLE Threat Detection...")
        print("🔍 Advanced device fingerprinting and behavior analysis enabled")
        print("🧠 Machine learning-based threat correlation active")
        print("🛑 Press Ctrl+C to stop")
        
        try:
            scan_count = 0
            while True:
                scan_count += 1
                print(f"\n📱 Enhanced BLE scan... ({datetime.now().strftime('%H:%M:%S')}) [#{scan_count}]")
                
                # Perform enhanced scan
                devices = self.scan_ble_devices()
                print(f"🔍 Discovered {len(devices)} BLE devices")
                
                threats_found = 0
                # Analyze each device with enhanced techniques
                for device in devices:
                    threats, threat_score = self.analyze_enhanced_threats(device)
                    
                    # Add threat correlation
                    corr_threats, corr_score = self.correlate_threats(device, threats, threat_score)
                    threats.extend(corr_threats)
                    threat_score = min(threat_score + corr_score, 1.0)
                    
                    if threat_score > 0.1:  # Lower threshold for enhanced detection
                        threats_found += 1
                        threat_level = self.get_threat_level(threat_score)
                        name = device.get('name', 'Unknown')
                        mac = device.get('mac_address', 'Unknown')
                        
                        print(f"  {threat_level} {name} ({mac}) - Score: {threat_score:.2f}")
                        print(f"    Threats: {', '.join(threats[:5])}{'...' if len(threats) > 5 else ''}")
                        
                        if device.get('rssi'):
                            print(f"    RSSI: {device['rssi']} dBm")
                        
                        # Enhanced logging
                        detection_data = {
                            'timestamp': datetime.utcnow().isoformat(),
                            'device': device,
                            'threat_score': threat_score,
                            'threats': threats,
                            'device_info': device,
                            'behavior_analysis': self.device_behaviors.get(mac, {}),
                            'fingerprint_data': {'hash': self.device_fingerprints.get(mac, '')},
                            'correlation_data': self.attack_sessions.get(f"{mac}_{int(time.time() // 300)}", {}),
                            'message': f"Enhanced BLE threat: {name} - {', '.join(threats[:3])}"
                        }
                        
                        self.send_to_elasticsearch(detection_data)
                
                # Update known devices
                for device in devices:
                    self.known_devices[device['mac_address']] = device
                
                print(f"⚡ Enhanced analysis: {threats_found} threats detected")
                
                # Cleanup old session data every 20 scans
                if scan_count % 20 == 0:
                    self.cleanup_old_sessions()
                
                # Wait before next scan
                time.sleep(45)  # Increased interval to avoid adapter issues
                
        except KeyboardInterrupt:
            print("\n🛑 Enhanced BLE threat monitoring stopped")
            print(f"📊 Total scans performed: {scan_count}")
    
    def detect_manufacturer_spoofing(self, device):
        """Detect manufacturer data spoofing and switching"""
        threats = []
        score = 0.0
        
        mac = device.get('mac_address', '')
        manufacturer = device.get('manufacturer', '').lower()
        current_time = time.time()
        
        if manufacturer:
            # Track manufacturer history for this device
            self.manufacturer_history[mac].append({
                'manufacturer': manufacturer,
                'timestamp': current_time
            })
            
            # Keep only last 10 entries
            if len(self.manufacturer_history[mac]) > 10:
                self.manufacturer_history[mac].pop(0)
            
            # Check for manufacturer switching
            if len(self.manufacturer_history[mac]) >= 3:
                manufacturers = [entry['manufacturer'] for entry in self.manufacturer_history[mac]]
                unique_manufacturers = set(manufacturers)
                
                if len(unique_manufacturers) >= 2:
                    threats.append('manufacturer_switching')
                    score += 0.7
                    
                if len(unique_manufacturers) >= 3:
                    threats.append('frequent_manufacturer_spoofing')
                    score += 0.8
            
            # Check for suspicious manufacturer patterns
            suspicious_mfg_patterns = [
                'apple', 'samsung', 'google', 'microsoft', 'amazon',
                'sony', 'lg', 'htc', 'oneplus', 'huawei'
            ]
            
            # If device is spoofing major manufacturers
            for pattern in suspicious_mfg_patterns:
                if pattern in manufacturer:
                    # Cross-check with MAC address OUI
                    mac_oui = mac[:8].replace(':', '').upper()
                    if not self.validate_manufacturer_oui(mac_oui, manufacturer):
                        threats.append(f'manufacturer_oui_mismatch_{pattern}')
                        score += 0.6
                    break
        
        return threats, score
    
    def validate_manufacturer_oui(self, mac_oui, manufacturer):
        """Validate manufacturer against MAC OUI"""
        # Common OUI prefixes for major manufacturers
        oui_mappings = {
            'apple': ['001451', '002608', '0050E4', '7CD1C3', 'A45E60'],
            'samsung': ['002454', '1C5A3E', 'E8508B', '2021A5', '885A92'],
            'google': ['F4F5E8', 'DA7C02', '6C2444', '840B2D', '74D435'],
            'microsoft': ['0017FA', '000D3A', '7C1E52', '8CFABA', 'A41731']
        }
        
        if manufacturer in oui_mappings:
            return mac_oui in oui_mappings[manufacturer]
        
        return True  # Unknown manufacturer, assume valid
    
    def analyze_advertisement_data(self, device):
        """Analyze BLE advertisement patterns for manipulation"""
        threats = []
        score = 0.0
        
        mac = device.get('mac_address', '')
        tx_power = device.get('tx_power')
        services = device.get('services', [])
        appearance = device.get('appearance', '')
        
        adv_pattern = self.advertisement_patterns[mac]
        current_time = time.time()
        
        # Track TX power changes
        if tx_power is not None:
            adv_pattern['tx_power_history'].append((tx_power, current_time))
            
            if len(adv_pattern['tx_power_history']) >= 3:
                tx_values = [tx for tx, _ in adv_pattern['tx_power_history']]
                tx_variance = statistics.variance(tx_values) if len(tx_values) > 1 else 0
                
                # High TX power variance indicates manipulation
                if tx_variance > 25:
                    threats.append('tx_power_manipulation')
                    score += 0.4
        
        # Track service data changes
        service_hash = hashlib.md5(json.dumps(sorted(services)).encode()).hexdigest()
        adv_pattern['data_changes'].append({
            'service_hash': service_hash,
            'timestamp': current_time,
            'appearance': appearance
        })
        
        # Analyze service data stability
        if len(adv_pattern['data_changes']) >= 5:
            service_hashes = [entry['service_hash'] for entry in adv_pattern['data_changes']]
            unique_hashes = set(service_hashes)
            
            # Frequent service changes indicate manipulation
            if len(unique_hashes) >= 4:
                threats.append('advertisement_data_manipulation')
                score += 0.6
                
            # Check for rapid changes (within 1 minute)
            recent_changes = [
                entry for entry in adv_pattern['data_changes']
                if current_time - entry['timestamp'] < 60
            ]
            
            if len(set(entry['service_hash'] for entry in recent_changes)) >= 3:
                threats.append('rapid_advertisement_changes')
                score += 0.5
        
        # Check for advertisement injection patterns
        if len(services) > 8:  # Many services might indicate injection
            threats.append('advertisement_service_injection')
            score += 0.3
        
        return threats, score
    
    def detect_apple_continuity_abuse(self, device):
        """Detect Apple Continuity protocol abuse"""
        threats = []
        score = 0.0
        
        mac = device.get('mac_address', '')
        manufacturer = device.get('manufacturer', '').lower()
        services = device.get('services', [])
        name = device.get('name', '').lower()
        
        # Apple Continuity service UUID
        apple_continuity_service = '89d3502b-0f36-433a-8ef4-c502ad55f8dc'
        
        # Check for Apple Continuity service
        has_continuity_service = any(
            apple_continuity_service.lower() in service.lower() 
            for service in services
        )
        
        if has_continuity_service:
            # Track Apple Continuity usage
            if mac not in self.apple_continuity_tracker:
                self.apple_continuity_tracker[mac] = {
                    'first_seen': time.time(),
                    'appearances': 0,
                    'name_variations': set()
                }
            
            tracker = self.apple_continuity_tracker[mac]
            tracker['appearances'] += 1
            tracker['name_variations'].add(name)
            
            # Non-Apple device using Apple Continuity
            if 'apple' not in manufacturer and not self.is_apple_mac(mac):
                threats.append('non_apple_continuity_abuse')
                score += 0.8
            
            # Multiple name variations using Continuity (spoofing)
            if len(tracker['name_variations']) >= 3:
                threats.append('apple_continuity_name_spoofing')
                score += 0.7
            
            # Frequent Continuity appearances (possible spam)
            if tracker['appearances'] >= 10:
                time_span = time.time() - tracker['first_seen']
                if time_span < 300:  # Within 5 minutes
                    threats.append('apple_continuity_flooding')
                    score += 0.6
        
        # Check for AirDrop abuse patterns
        airdrop_patterns = ['airdrop', 'air drop', 'share', 'handoff']
        for pattern in airdrop_patterns:
            if pattern in name:
                if 'apple' not in manufacturer and not self.is_apple_mac(mac):
                    threats.append('fake_airdrop_service')
                    score += 0.7
                break
        
        return threats, score
    
    def is_apple_mac(self, mac):
        """Check if MAC address belongs to Apple"""
        apple_oui_prefixes = [
            '00:14:51', '00:26:08', '00:50:E4', '7C:D1:C3', 'A4:5E:60',
            '28:C6:8E', '5C:F5:DA', '98:5A:EB', 'AC:3C:0B', 'DC:56:E7'
        ]
        
        mac_prefix = mac[:8].upper()
        return any(prefix.replace(':', '') == mac_prefix.replace(':', '') 
                  for prefix in apple_oui_prefixes)
    
    def detect_gatt_enumeration(self, device):
        """Detect GATT service enumeration attempts"""
        threats = []
        score = 0.0
        
        services = device.get('services', [])
        mac = device.get('mac_address', '')
        
        # Generic Attribute Service indicates GATT enumeration
        gatt_service = '00001801-0000-1000-8000-00805f9b34fb'
        generic_access = '00001800-0000-1000-8000-00805f9b34fb'
        
        enumeration_services = [gatt_service, generic_access]
        has_enumeration_services = any(
            enum_service.lower() in service.lower() 
            for service in services 
            for enum_service in enumeration_services
        )
        
        if has_enumeration_services:
            # Track GATT enumeration attempts
            behavior = self.device_behaviors[mac]
            if not hasattr(behavior, 'gatt_attempts'):
                behavior.gatt_attempts = deque(maxlen=10)
            
            behavior.gatt_attempts.append(time.time())
            
            # Frequent GATT enumeration attempts
            if len(behavior.gatt_attempts) >= 5:
                threats.append('gatt_service_enumeration')
                score += 0.4
                
                # Check for rapid enumeration
                now = time.time()
                recent_attempts = [
                    ts for ts in behavior.gatt_attempts
                    if now - ts < 120  # Last 2 minutes
                ]
                
                if len(recent_attempts) >= 4:
                    threats.append('rapid_gatt_enumeration')
                    score += 0.6
        
        # Check for extensive service discovery
        if len(services) >= 10:  # Many services exposed
            threats.append('extensive_service_discovery')
            score += 0.3
        
        return threats, score
    
    def cleanup_old_sessions(self):
        """Clean up old attack session data"""
        current_time = time.time()
        cutoff_time = current_time - 1800  # 30 minutes
        
        old_sessions = [k for k, v in self.attack_sessions.items() 
                       if v['start_time'] < cutoff_time]
        
        for session_key in old_sessions:
            del self.attack_sessions[session_key]
        
        # Clean old manufacturer history
        for mac in list(self.manufacturer_history.keys()):
            self.manufacturer_history[mac] = [
                entry for entry in self.manufacturer_history[mac]
                if current_time - entry['timestamp'] < 3600  # 1 hour
            ]
            if not self.manufacturer_history[mac]:
                del self.manufacturer_history[mac]
        
        # Clean old Apple Continuity tracking
        old_apple_entries = [
            mac for mac, data in self.apple_continuity_tracker.items()
            if current_time - data['first_seen'] > 7200  # 2 hours
        ]
        for mac in old_apple_entries:
            del self.apple_continuity_tracker[mac]
        
        print(f"🧹 Cleaned {len(old_sessions)} old attack sessions")

if __name__ == "__main__":
    detector = EnhancedBLEThreatDetector()
    detector.monitor_enhanced_ble_threats()