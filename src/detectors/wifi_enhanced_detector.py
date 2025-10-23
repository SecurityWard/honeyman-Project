#!/usr/bin/env python3
"""
Enhanced WiFi Threat Detection System
Accurate evil twin, deauth, and WiFi attack detection with advanced filtering
"""
import subprocess
import time
import json
import re
import logging
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict, deque
from elasticsearch import Elasticsearch

# Configure logging  
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/burner/honeypot-minimal/logs/wifi_enhanced.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class EnhancedWiFiDetector:
    def __init__(self):
        # Elasticsearch connection
        self.es = Elasticsearch(['http://localhost:9200'])
        
        # Network tracking with enhanced behavior analysis
        self.known_networks = {}
        self.network_history = defaultdict(lambda: {
            'bssids': set(),
            'channels': set(),
            'encryptions': set(),
            'signal_history': deque(maxlen=50),
            'first_seen': None,
            'last_seen': None,
            'beacon_count': 0,
            'client_count': 0
        })
        
        # Enhanced deduplication and rate limiting
        self.recent_threats = {}  # hash -> timestamp
        self.threat_cooldown = 300  # 5 minutes between duplicate alerts
        self.network_whitelist = set()  # Trusted network BSSIDs
        self.ssid_whitelist = set()    # Trusted SSIDs
        
        # Load whitelist configuration
        self.load_whitelist_config()
        
        # Enhanced evil twin detection patterns (from fixed logic)
        self.evil_twin_patterns = {
            'same_ssid_different_bssid': {
                'description': 'Multiple BSSIDs for same SSID - Sophisticated filtering applied to reduce false positives',
                'score': 0.8
            },
            'same_ssid_different_encryption': {
                'description': 'Same SSID with different encryption - Security downgrade attack detected',
                'score': 0.9
            },
            'open_version_of_secure': {
                'description': 'Open network mimicking secure network - Classic evil twin tactic',
                'score': 0.95
            },
            'signal_anomaly': {
                'description': 'Suspicious signal strength for known network - Possible proximity attack',
                'score': 0.7
            },
            'channel_hopping': {
                'description': 'Network changing channels rapidly - Evasion technique',
                'score': 0.75
            },
            'karma_attack': {
                'description': 'Access point responding to all probe requests - KARMA/Jasager attack',
                'score': 0.85
            }
        }
        
        # WiFi attack signatures (from BSides detector)
        self.wifi_attacks = {
            'deauth_flood': {
                'patterns': ['deauthentication', 'deauth flood', 'disassociation'],
                'threshold': 10,  # deauths per minute
                'description': 'Deauthentication flood attack - Forces clients to disconnect and potentially connect to rogue AP',
                'score': 0.9
            },
            'beacon_flood': {
                'patterns': ['beacon flood', 'ssid flood', 'spam'],
                'threshold': 50,  # new SSIDs per scan
                'description': 'Beacon flooding attack - Overwhelming wireless environment with fake access points',
                'score': 0.8
            },
            'pmkid_attack': {
                'patterns': ['pmkid', 'clientless', 'hashcat'],
                'indicators': ['no_clients', 'wpa2', 'targeted'],
                'description': 'PMKID attack - Capturing WPA2 handshakes without clients for offline cracking',
                'score': 0.85
            },
            'krack_attack': {
                'patterns': ['key reinstallation', 'krack', 'wpa2 vulnerability'],
                'indicators': ['replay_counter', 'nonce_reuse'],
                'description': 'KRACK attack - Key reinstallation attack against WPA2 protocol',
                'score': 0.9
            },
            'fragmentation_attack': {
                'patterns': ['frag attack', 'fragmentation', 'aggregation'],
                'description': 'FragAttacks - Exploiting frame aggregation and fragmentation vulnerabilities',
                'score': 0.85
            },
            'wps_pixie': {
                'patterns': ['wps', 'pixie dust', 'pin attack'],
                'indicators': ['wps_enabled', 'rapid_attempts'],
                'description': 'WPS Pixie Dust attack - Exploiting weak random number generation in WPS',
                'score': 0.8
            }
        }
        
        # Hacking tool signatures (from BSides detector)
        self.hacking_tools = {
            'pineapple': {
                'ssids': ['Pineapple', 'PineAP', 'MANA', 'Karma'],
                'oui': ['00:13:37', '00:C0:CA'],  # Pineapple MACs
                'behaviors': ['karma_responses', 'portal_cloning'],
                'description': 'WiFi Pineapple - Professional penetration testing access point',
                'score': 0.95
            },
            'flipper_wifi': {
                'ssids': ['Flipper', 'FlipperZero', 'Marauder'],
                'behaviors': ['deauth_capability', 'packet_injection'],
                'description': 'Flipper Zero WiFi module - Multi-tool device with WiFi attack capabilities',
                'score': 0.9
            },
            'esp8266_deauther': {
                'ssids': ['pwned', 'deauther', 'esp8266'],
                'oui': ['5C:CF:7F', 'EC:FA:BC', '2C:3A:E8'],  # ESP OUIs
                'behaviors': ['continuous_deauth', 'beacon_spam'],
                'description': 'ESP8266 Deauther - DIY WiFi attack tool based on ESP8266 microcontroller',
                'score': 0.85
            },
            'esp32_marauder': {
                'ssids': ['Marauder', 'ESP32', 'WiFiMarauder'],
                'behaviors': ['packet_monitor', 'deauth', 'evil_portal'],
                'description': 'ESP32 Marauder - Advanced WiFi testing tool with multiple attack vectors',
                'score': 0.85
            },
            'aircrack_suite': {
                'indicators': ['mon0', 'wlan0mon', 'airodump'],
                'behaviors': ['channel_hopping', 'packet_injection'],
                'description': 'Aircrack-ng suite - Professional WiFi security auditing tools',
                'score': 0.8
            }
        }
        
        # Suspicious SSID patterns (from BSides detector)
        self.suspicious_ssids = {
            'setup_pages': [
                r'.*[Ss]etup.*',
                r'.*[Cc]onfig.*',
                r'.*[Aa]dmin.*',
                r'DIRECT-.*',
                r'.*_nomap'
            ],
            'honeypots': [
                r'Free.*WiFi',
                r'Open.*WiFi',
                r'Public.*WiFi',
                r'.*_Free',
                r'.*Guest.*',
                r'.*Complimentary.*'
            ],
            'default_passwords': [
                r'NETGEAR\d+',
                r'Linksys\d+',
                r'dlink-.*',
                r'TP-LINK_.*',
                r'ASUS.*'
            ],
            'pranks': [
                r'.*[Pp]orn.*',
                r'.*FBI.*',
                r'.*NSA.*',
                r'.*Surveillance.*',
                r'.*Virus.*',
                r'.*[Hh]ack.*'
            ],
            'attack_tools': [
                r'.*[Pp]wn.*',
                r'.*[Hh]ack.*',
                r'.*[Ee]xploit.*',
                r'.*[Cc]rack.*'
            ]
        }
        
        # Attack correlation tracking
        self.deauth_tracker = defaultdict(lambda: deque(maxlen=100))
        self.beacon_tracker = defaultdict(int)
        self.client_tracker = defaultdict(set)
        
        # Interface management
        self.interface = None
        self.monitor_mode = False
        
    def load_whitelist_config(self):
        """Load whitelist configuration from file (compatible with existing logic)"""
        try:
            with open('/home/burner/honeypot-minimal/wifi_whitelist.json', 'r') as f:
                config = json.load(f)
                self.network_whitelist.update(config.get('bssid_whitelist', []))
                self.ssid_whitelist.update(config.get('ssid_whitelist', []))
                logger.info(f"📋 Loaded {len(self.network_whitelist)} whitelisted BSSIDs and {len(self.ssid_whitelist)} SSIDs")
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
            logger.info("📋 Created default whitelist config at wifi_whitelist.json")
        except Exception as e:
            logger.warning(f"⚠️ Error loading whitelist: {e}")
    
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
            self.interface = self.detect_wifi_interface()
            
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
            logger.warning("⚠️ WiFi scan timeout")
        except Exception as e:
            logger.error(f"❌ WiFi scan error: {e}")
            
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
    
    def detect_evil_twin_advanced(self, network, current_bssid):
        """
        Advanced evil twin detection with sophisticated filtering to reduce false positives.
        
        An evil twin attack involves creating a fake access point with the same SSID as a legitimate one,
        but this is only suspicious under certain conditions:
        
        1. Sudden appearance of duplicate SSID in close proximity (strong signal)
        2. Security downgrade (open network mimicking secured one)
        3. Vendor OUI mismatch (different manufacturers for same network)
        4. Abnormal timing patterns (networks appearing/disappearing together)
        
        Returns:
            dict: {
                'is_evil_twin': bool,
                'confidence_score': float (0.1-0.9),
                'reasons': list of detection reasons,
                'explanation': detailed explanation
            }
        """
        result = {
            'is_evil_twin': False,
            'confidence_score': 0.0,
            'reasons': [],
            'explanation': ''
        }
        
        ssid = network.get('ssid', '')
        current_signal = network.get('signal', '0')
        current_security = network.get('security', [])
        
        # Find all networks with the same SSID
        same_ssid_networks = []
        for known_bssid, known_network in self.known_networks.items():
            if (known_network['ssid'] == ssid and known_bssid != current_bssid):
                same_ssid_networks.append((known_bssid, known_network))
        
        # If no duplicates, not an evil twin scenario
        if not same_ssid_networks:
            return result
        
        # Check for legitimate multi-AP scenarios first, but only if no other red flags
        is_likely_legitimate = self._is_legitimate_multi_ap_network(ssid, current_bssid, same_ssid_networks)
        
        # Even if it looks legitimate, still check for security downgrades and proximity issues
        has_security_issues = False
        has_proximity_issues = False
        
        for known_bssid, known_network in same_ssid_networks:
            known_security = known_network.get('security', [])
            # Check for security downgrade regardless of legitimacy
            if known_security and not current_security:
                has_security_issues = True
                break
                
            # Check for suspicious proximity
            try:
                current_sig_val = float(current_signal)
                known_sig_val = float(known_network.get('signal', '0'))
                if current_sig_val > -50 and known_sig_val > -50:
                    has_proximity_issues = True
                    break
            except (ValueError, TypeError):
                pass
        
        # If it looks legitimate AND has no major red flags, skip detection
        if is_likely_legitimate and not has_security_issues and not has_proximity_issues:
            result['explanation'] = f"Multiple APs for '{ssid}' detected but consistent with legitimate enterprise/mesh network based on OUI patterns and security consistency"
            return result
        
        # Now analyze for actual evil twin indicators
        confidence_factors = []
        
        for known_bssid, known_network in same_ssid_networks:
            known_signal = known_network.get('signal', '0')
            known_security = known_network.get('security', [])
            
            # Factor 1: Signal strength analysis (proximity-based suspicion)
            try:
                current_sig_val = float(current_signal)
                known_sig_val = float(known_signal)
                
                # Both networks have strong signals (within ~30 meters) - suspicious
                if current_sig_val > -50 and known_sig_val > -50:
                    confidence_factors.append(0.3)
                    result['reasons'].append("proximity_suspicious_both_strong_signals")
                    
            except (ValueError, TypeError):
                pass
            
            # Factor 2: Security downgrade attack (most common evil twin tactic)
            if known_security and not current_security:
                confidence_factors.append(0.4)
                result['reasons'].append("security_downgrade_open_vs_secured")
            elif set(known_security) != set(current_security):
                confidence_factors.append(0.2)
                result['reasons'].append("security_configuration_mismatch")
            
            # Factor 3: Vendor OUI analysis (different manufacturers suspicious)
            current_oui = current_bssid[:8].lower() if len(current_bssid) >= 8 else ""
            known_oui = known_bssid[:8].lower() if len(known_bssid) >= 8 else ""
            
            if current_oui and known_oui and current_oui != known_oui:
                # Different vendors for same network name is suspicious
                if not self._is_common_oui_pairing(current_oui, known_oui):
                    confidence_factors.append(0.3)
                    result['reasons'].append("vendor_oui_mismatch_suspicious")
        
        # Calculate final confidence score
        if confidence_factors:
            # Use weighted average, cap at 0.9 to avoid overconfidence
            result['confidence_score'] = min(0.9, sum(confidence_factors) / len(confidence_factors))
            
            # Only flag as evil twin if we have substantial evidence
            if result['confidence_score'] >= 0.3:
                result['is_evil_twin'] = True
                result['explanation'] = f"Evil twin attack detected for SSID '{ssid}': {', '.join(result['reasons'])}. Confidence: {result['confidence_score']:.2f}"
            else:
                result['explanation'] = f"Potential evil twin for '{ssid}' but confidence too low ({result['confidence_score']:.2f}), likely legitimate multi-AP setup"
        else:
            result['explanation'] = f"Multiple APs for '{ssid}' appear to be legitimate based on consistent security and vendor patterns"
        
        return result
    
    def _is_legitimate_multi_ap_network(self, ssid, current_bssid, same_ssid_networks):
        """
        Determine if multiple APs with same SSID represent legitimate infrastructure.
        
        Common legitimate scenarios:
        - Enterprise networks (consistent OUI prefixes from same vendor)
        - Mesh systems (vendors like Eero, Orbi often use same base OUI)
        - Home extenders (usually same vendor as main router)
        - Public hotspots (Starbucks, McDonald's, etc. often have same vendor equipment)
        """
        # Extract OUI (first 3 octets) from current BSSID
        current_oui = current_bssid[:8].lower() if len(current_bssid) >= 8 else ""
        
        # Check if most/all networks share same OUI vendor
        same_vendor_count = 0
        total_networks = len(same_ssid_networks)
        
        for known_bssid, _ in same_ssid_networks:
            known_oui = known_bssid[:8].lower() if len(known_bssid) >= 8 else ""
            if current_oui == known_oui:
                same_vendor_count += 1
        
        # If 70%+ share same vendor OUI, likely legitimate
        same_vendor_ratio = same_vendor_count / total_networks if total_networks > 0 else 0
        
        # Enterprise/mesh network indicators
        enterprise_ssid_patterns = [
            'guest', 'visitor', 'corp', 'office', 'employee',
            'eduroam', 'university', 'hospital', 'hotel'
        ]
        
        is_likely_enterprise = any(pattern in ssid.lower() for pattern in enterprise_ssid_patterns)
        
        # Common public hotspot patterns
        public_hotspot_patterns = [
            'starbucks', 'mcdonalds', 'attwifi', 'xfinity', 'comcast',
            'airport', 'mall', 'retail'
        ]
        
        is_likely_public = any(pattern in ssid.lower() for pattern in public_hotspot_patterns)
        
        return (same_vendor_ratio >= 0.7) or is_likely_enterprise or is_likely_public
    
    def _is_common_oui_pairing(self, oui1, oui2):
        """
        Check if two different OUIs commonly appear together in legitimate networks.
        Some vendors use multiple OUI ranges or partner equipment.
        """
        # Common legitimate OUI pairings (simplified list)
        common_pairings = [
            # Cisco equipment often mixed
            {'00:1b:d5', '00:26:ca', '00:23:04'},
            # Apple ecosystem
            {'00:17:f2', '00:1f:f3', '00:25:00'},
            # Ubiquiti networks
            {'00:15:6d', '04:18:d6', '24:a4:3c'},
        ]
        
        for pairing in common_pairings:
            if oui1 in pairing and oui2 in pairing:
                return True
        
        return False
    
    def check_hacking_tools(self, network):
        """Check for known WiFi hacking tools and attack devices"""
        threats = []
        total_score = 0.0
        
        ssid = network.get('ssid', '').lower()
        bssid = network.get('bssid', '').lower()
        
        for tool_name, tool_info in self.hacking_tools.items():
            tool_detected = False
            
            # Check SSID patterns
            for pattern in tool_info.get('ssids', []):
                if pattern.lower() in ssid:
                    tool_detected = True
                    break
            
            # Check OUI patterns
            for oui in tool_info.get('oui', []):
                if bssid.startswith(oui.lower().replace(':', '')):
                    tool_detected = True
                    break
            
            if tool_detected:
                threats.append({
                    'type': f'hacking_tool_{tool_name}',
                    'confidence': tool_info['score'],
                    'details': tool_info['description']
                })
                total_score = max(total_score, tool_info['score'])
        
        return threats, total_score
    
    def check_suspicious_ssids(self, network):
        """Check for suspicious SSID patterns"""
        threats = []
        total_score = 0.0
        
        ssid = network.get('ssid', '')
        
        for category, patterns in self.suspicious_ssids.items():
            for pattern in patterns:
                if re.search(pattern, ssid, re.IGNORECASE):
                    threats.append({
                        'type': f'suspicious_ssid_{category}',
                        'confidence': 0.6,
                        'details': f"SSID '{ssid}' matches suspicious pattern for {category} - Possible social engineering or attack tool"
                    })
                    total_score = max(total_score, 0.6)
                    break
        
        return threats, total_score
    
    def analyze_network_threats(self, network):
        """Comprehensive network threat analysis with enhanced explanations"""
        threats = []
        threat_score = 0.0
        
        # Skip whitelisted networks
        if self.is_whitelisted(network):
            return threats, threat_score
        
        ssid = network.get('ssid', '')
        bssid = network.get('bssid', '')
        security = network.get('security', [])
        
        # Enhanced evil twin detection with fixed logic
        if ssid and len(ssid) > 2:  # Only for non-empty, meaningful SSIDs
            evil_twin_result = self.detect_evil_twin_advanced(network, bssid)
            if evil_twin_result['is_evil_twin']:
                threat_hash = self.create_threat_hash(network, "evil_twin_detected")
                if not self.is_threat_duplicate(threat_hash):
                    threats.append({
                        'type': 'evil_twin_detected',
                        'confidence': evil_twin_result['confidence_score'],
                        'details': evil_twin_result['explanation']
                    })
                    threat_score = max(threat_score, evil_twin_result['confidence_score'])
        
        # Check for hacking tools
        tool_threats, tool_score = self.check_hacking_tools(network)
        threats.extend(tool_threats)
        threat_score = max(threat_score, tool_score)
        
        # Check suspicious SSIDs
        ssid_threats, ssid_score = self.check_suspicious_ssids(network)
        threats.extend(ssid_threats)
        threat_score = max(threat_score, ssid_score)
        
        # Check for weak security (but less aggressive)
        if 'WEP' in security:  # Only WEP is truly weak, open networks are often legitimate
            threat_hash = self.create_threat_hash(network, "weak_encryption_wep")
            if not self.is_threat_duplicate(threat_hash):
                threats.append({
                    'type': 'weak_encryption_wep',
                    'confidence': 0.3,
                    'details': f"Network '{ssid}' uses WEP encryption - Easily crackable within minutes, presents significant security risk"
                })
                threat_score = max(threat_score, 0.3)
        
        # Check for unusual signal strength patterns (suspicious proximity)
        try:
            signal = float(network.get('signal', 0))
            if signal > -10:  # Very strong signal (likely very close/malicious)
                threat_hash = self.create_threat_hash(network, "suspicious_proximity")
                if not self.is_threat_duplicate(threat_hash):
                    threats.append({
                        'type': 'suspicious_proximity',
                        'confidence': 0.3,
                        'details': f"Network '{ssid}' has unusually strong signal ({signal}dBm) - Possible rogue AP in close proximity for man-in-the-middle attacks"
                    })
                    threat_score = max(threat_score, 0.3)
        except:
            pass
        
        # Only flag hidden SSIDs if they have other suspicious characteristics
        if not ssid and len(security) == 0:  # Hidden AND open = suspicious
            threat_hash = self.create_threat_hash(network, "hidden_open_network")
            if not self.is_threat_duplicate(threat_hash):
                threats.append({
                    'type': 'hidden_open_network',
                    'confidence': 0.2,
                    'details': f"Hidden SSID with no security - Unusual combination that may indicate surveillance or attack infrastructure"
                })
                threat_score = max(threat_score, 0.2)
        
        return threats, min(threat_score, 1.0)
    
    def detect_beacon_flooding(self, networks):
        """Detect beacon flooding attacks with improved thresholds"""
        current_time = time.time()
        flooding_networks = []
        
        for network in networks:
            bssid = network['bssid']
            
            # Track beacon timestamps (simplified for iwlist)
            self.beacon_tracker[bssid] += 1
            
            # Reset counter every minute
            if not hasattr(self, 'last_reset') or current_time - self.last_reset > 60:
                self.beacon_tracker.clear()
                self.last_reset = current_time
            
            # Check for flooding (>20 appearances per scan indicates rapid beaconing)
            if self.beacon_tracker[bssid] > 20:
                threat_hash = self.create_threat_hash(network, "beacon_flooding")
                if not self.is_threat_duplicate(threat_hash):
                    flooding_networks.append({
                        'bssid': bssid,
                        'ssid': network.get('ssid', 'Hidden'),
                        'beacon_rate': self.beacon_tracker[bssid],
                        'threat_type': 'beacon_flooding',
                        'description': f"Beacon flooding attack detected - {self.beacon_tracker[bssid]} rapid beacon transmissions overwhelming wireless environment"
                    })
        
        return flooding_networks
    
    def send_to_elasticsearch(self, detection_data):
        """Send WiFi threat detection to Elasticsearch with enhanced logging"""
        try:
            doc = {
                'timestamp': detection_data['timestamp'],
                'honeypot_id': 'honeyman-01',
                'source': 'wifi_enhanced_detector',
                'log_type': 'wifi_threat_detection',
                'interface': self.interface,
                'detection_type': detection_data['type'],
                'threat_score': detection_data['threat_score'],
                'threats_detected': detection_data['threats'],
                'network_info': detection_data['network_info'],
                'message': detection_data['message'],
                'explanation': detection_data.get('explanation', '')
            }
            
            response = self.es.index(index='honeypot-logs-new', document=doc)
            
            if response.get('result') in ['created', 'updated']:
                logger.info(f"✅ WiFi threat logged to Elasticsearch")
            else:
                logger.warning(f"❌ Failed to log WiFi threat: {response}")
                
        except Exception as e:
            logger.error(f"❌ Elasticsearch error: {e}")
    
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
        """Main WiFi threat monitoring loop with enhanced detection"""
        logger.info("🚀 Starting Enhanced WiFi Detector")
        logger.info("🎯 Focus: Evil twins, WiFi attacks, hacking tools")
        
        if not self.interface:
            self.interface = self.detect_wifi_interface()
            
        if not self.interface:
            logger.error("❌ No WiFi interface available")
            return
            
        logger.info(f"🔍 Monitoring interface: {self.interface}")
        logger.info(f"⏱️ Threat cooldown: {self.threat_cooldown}s")
        logger.info(f"📋 Whitelisted: {len(self.network_whitelist)} BSSIDs, {len(self.ssid_whitelist)} SSIDs")
        logger.info("💡 Scanning for wireless threats with enhanced filtering...")
        logger.info("🛑 Press Ctrl+C to stop")
        
        scan_count = 0
        try:
            while True:
                scan_count += 1
                logger.info(f"\n📡 Scanning networks... ({datetime.now().strftime('%H:%M:%S')}) [Scan #{scan_count}]")
                
                # Clean up old data every 10 scans
                if scan_count % 10 == 0:
                    self.cleanup_old_threats()
                    logger.info(f"🧹 Cleaned {len(self.recent_threats)} tracked threats")
                
                # Scan for networks
                networks = self.scan_networks()
                logger.info(f"🔍 Found {len(networks)} networks")
                
                threats_found = 0
                # Analyze each network for threats
                for network in networks:
                    threats, threat_score = self.analyze_network_threats(network)
                    
                    if threats:
                        threats_found += 1
                        threat_level = self.get_threat_level(threat_score)
                        ssid = network.get('ssid', 'Hidden')
                        bssid = network.get('bssid', 'Unknown')
                        
                        logger.info(f"  {threat_level} {ssid} ({bssid})")
                        
                        # Log details for each threat
                        for threat in threats:
                            logger.info(f"    {threat['type']}: {threat.get('details', 'No details')}")
                        
                        # Enhanced logging with detailed explanations
                        explanation = ' | '.join([t.get('details', '') for t in threats])
                        
                        detection_data = {
                            'timestamp': datetime.utcnow().isoformat(),
                            'type': 'suspicious_network',
                            'threat_score': threat_score,
                            'threats': [t['type'] for t in threats],
                            'network_info': network,
                            'message': f"Enhanced WiFi threat detected: {ssid} - {', '.join([t['type'] for t in threats])}",
                            'explanation': explanation
                        }
                        
                        self.send_to_elasticsearch(detection_data)
                
                # Check for beacon flooding
                flooding = self.detect_beacon_flooding(networks)
                for flood_network in flooding:
                    threats_found += 1
                    logger.warning(f"  🚨 CRITICAL Beacon flooding: {flood_network['ssid']} ({flood_network['beacon_rate']} rapid beacons)")
                    logger.info(f"    Details: {flood_network['description']}")
                    
                    detection_data = {
                        'timestamp': datetime.utcnow().isoformat(),
                        'type': 'beacon_flooding',
                        'threat_score': 0.9,
                        'threats': ['beacon_flooding'],
                        'network_info': flood_network,
                        'message': f"Beacon flooding attack detected: {flood_network['beacon_rate']} rapid beacons",
                        'explanation': flood_network['description']
                    }
                    
                    self.send_to_elasticsearch(detection_data)
                
                logger.info(f"⚡ {threats_found} threats detected in this scan")
                
                # Update known networks
                for network in networks:
                    self.known_networks[network['bssid']] = network
                
                # Wait before next scan
                time.sleep(15)
                
        except KeyboardInterrupt:
            logger.info("\n🛑 Enhanced WiFi detector stopped")
            logger.info(f"📊 Total scans performed: {scan_count}")

if __name__ == "__main__":
    detector = EnhancedWiFiDetector()
    detector.monitor_wifi_threats()