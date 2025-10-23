#!/usr/bin/env python3
"""
Enhanced USB Threat Detection System
Accurate BadUSB, Rubber Ducky, and malicious USB detection
"""
import subprocess
import time
import json
import re
import os
import hashlib
import logging
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict, deque
from elasticsearch import Elasticsearch
import pyudev
import struct

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/burner/honeypot-minimal/logs/usb_enhanced.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class EnhancedUSBDetector:
    # System devices that should be whitelisted (not analyzed as threats)
    # Format: (VID, PID) or (VID, None) for all PIDs from that vendor
    SYSTEM_DEVICE_WHITELIST = {
        ('046d', None): 'Logitech peripherals (keyboard, mouse, receivers)',
        ('1d6b', None): 'Linux Foundation USB hubs and controllers',
        ('8087', None): 'Intel Bluetooth adapters',
        ('0a5c', None): 'Broadcom Bluetooth adapters',
        ('0bda', None): 'Realtek card readers and network adapters',
    }

    def __init__(self):
        # Elasticsearch connection
        self.es = Elasticsearch(['http://localhost:9200'])

        # Malware hash database connection
        self.hash_db_path = "/home/burner/honeypot-minimal/data/malware_hashes.db"
        self.hash_db_conn = None
        self.init_hash_database()
        
        # USB device tracking
        self.known_devices = {}
        self.device_behaviors = defaultdict(lambda: {
            'mount_count': 0,
            'file_operations': deque(maxlen=100),
            'keystroke_timing': deque(maxlen=1000),
            'process_spawns': [],
            'network_connections': [],
            'first_seen': None,
            'last_seen': None
        })
        
        # Initialize udev context for USB monitoring
        self.context = pyudev.Context()
        self.monitor = pyudev.Monitor.from_netlink(self.context)
        self.monitor.filter_by('usb')
        
        # BadUSB signatures (updated with real-world patterns)
        self.badusb_signatures = {
            'rubber_ducky': {
                'vid_pid': [
                    ('03eb', '2401'),  # ATMEL DFU
                    ('16c0', '05dc'),  # USBaspLoader
                    ('16c0', '047c'),  # Teensy
                    ('1b4f', '9206'),  # Arduino Leonardo
                    ('2341', '0036'),  # Arduino Leonardo
                    ('2341', '8036'),  # Arduino Leonardo
                    ('2a03', '0036'),  # Arduino Leonardo
                    ('1209', '2100'),  # Digispark
                ],
                'behaviors': ['rapid_keystrokes', 'no_user_interaction', 'command_patterns'],
                'score': 0.95
            },
            'bash_bunny': {
                'vid_pid': [
                    ('f000', 'ff00'),  # Bash Bunny
                    ('f000', 'ff01'),  # Bash Bunny Storage
                    ('f000', 'ff02'),  # Bash Bunny Network
                ],
                'behaviors': ['mode_switching', 'network_adapter', 'storage_and_hid'],
                'score': 0.98
            },
            'omg_cable': {
                'vid_pid': [
                    ('05ac', '024f'),  # Apple Lightning (spoofed)
                    ('05ac', '12a8'),  # Apple USB-C (spoofed)
                    ('05ac', '1460'),  # Apple USB-C (spoofed)
                    ('1d6b', '0104'),  # Linux Foundation (generic)
                ],
                'product_strings': ['O.MG', 'OMG', 'Elite', 'Cable'],
                'behaviors': ['wifi_beacon', 'remote_payload', 'legitimate_looking'],
                'score': 0.95
            },
            'malduino': {
                'vid_pid': [
                    ('1209', 'bad1'),  # Malduino Elite
                    ('1209', 'bad2'),  # Malduino W
                    ('16c0', '05dc'),  # Malduino (ATMEL based)
                ],
                'product_strings': ['Malduino', 'BadUSB'],
                'score': 0.95
            },
            'usb_ninja': {
                'behaviors': ['bluetooth_control', 'remote_trigger', 'delayed_execution'],
                'indicators': ['unexpected_wireless', 'time_based_trigger'],
                'score': 0.85
            },
            'flipper_zero_usb': {
                'vid_pid': [
                    ('0483', '5740'),  # STM32 (Flipper)
                ],
                'product_strings': ['Flipper', 'FZ_', 'BadUSB'],
                'behaviors': ['hid_emulation', 'script_execution'],
                'score': 0.9
            },
            'pwnpi': {
                'behaviors': ['network_bridge', 'reverse_shell', 'persistence'],
                'indicators': ['raspberry_pi_zero', 'gadget_mode'],
                'score': 0.85
            }
        }
        
        # Malicious USB behaviors
        self.malicious_behaviors = {
            'keystroke_injection': {
                'patterns': [
                    r'cmd\.exe',
                    r'powershell',
                    r'/bin/bash',
                    r'curl.*\|.*sh',
                    r'wget.*&&',
                    r'nc\s+-[lenv]',
                    r'reverse.*shell',
                    r'meterpreter',
                    r'empire',
                    r'mimikatz',
                    r'invoke-.*'
                ],
                'timing': 'superhuman',  # < 10ms between keystrokes
                'score': 0.9
            },
            'autorun_abuse': {
                'files': [
                    'autorun.inf',
                    'desktop.ini',
                    '.DS_Store',
                    'Thumbs.db'
                ],
                'executables': [
                    '.exe', '.scr', '.bat', '.cmd', '.ps1',
                    '.vbs', '.js', '.jar', '.app'
                ],
                'score': 0.8
            },
            'firmware_attack': {
                'indicators': [
                    'DFU_mode',
                    'bootloader_access',
                    'firmware_update',
                    'flash_write'
                ],
                'score': 0.85
            },
            'data_exfiltration': {
                'patterns': [
                    'mass_file_copy',
                    'selective_copy',
                    'compression_before_copy',
                    'encrypted_container'
                ],
                'file_patterns': [
                    r'.*\.docx?$',
                    r'.*\.xlsx?$',
                    r'.*\.pdf$',
                    r'.*\.key$',
                    r'.*\.pem$',
                    r'.*password.*',
                    r'.*secret.*'
                ],
                'score': 0.75
            },
            'cryptominer': {
                'processes': ['xmrig', 'minergate', 'nicehash'],
                'indicators': ['high_cpu', 'network_to_pool'],
                'score': 0.7
            },
            'usb_killer': {
                'indicators': [
                    'voltage_surge',
                    'power_cycling',
                    'capacitor_charge',
                    'no_data_interface'
                ],
                'score': 0.95
            }
        }
        
        # Known malware signatures
        self.malware_signatures = {
            'stuxnet': {
                'files': ['mrxcls.sys', 'mrxnet.sys'],
                'registry': ['MRxCls', 'MRxNet'],
                'score': 0.99
            },
            'badusb_ps': {
                'patterns': ['IEX', 'DownloadString', 'Invoke-Expression'],
                'score': 0.85
            },
            'usb_trojan': {
                'behaviors': ['hidden_partition', 'bootkit', 'rootkit'],
                'score': 0.9
            }
        }
        
        # Suspicious volume label patterns
        self.suspicious_volume_labels = [
            r'.*[Ss]tark.*[Kk]iller.*',
            r'.*STARKILLER.*',
            r'.*[Pp]ayload.*',
            r'.*[Bb]ad[Uu][Ss][Bb].*',
            r'.*[Dd]ucky.*',
            r'.*[Rr]ubber.*',
            r'.*[Pp]wn.*',
            r'.*[Hh]ack.*',
            r'.*[Ee]xploit.*',
            r'.*[Mm]alware.*',
            r'.*[Bb]ackdoor.*',
            r'.*[Rr]ootkit.*',
            r'.*[Pp]oisontap.*',
            r'.*[Bb]ash.*[Bb]unny.*',
            r'.*[Nn]inja.*',
            r'.*O\.?M\.?G.*'
        ]
        
        # Known penetration testing USB device IDs
        self.known_attack_devices = {
            ('048d', '1167'): {
                'name': 'Potential Attack USB Device',
                'score': 0.8,
                'description': 'USB device with VID/PID associated with penetration testing tools'
            }
        }
        
        # Known mass storage device VID/PIDs (for reliable storage detection)
        self.known_storage_devices = {
            # SanDisk devices
            ('0781', '5567'): 'SanDisk Cruzer Blade',
            ('0781', '5575'): 'SanDisk Cruzer Glide',  # Current malicious USB
            ('0781', '5581'): 'SanDisk Ultra',
            ('0781', '5583'): 'SanDisk Ultra Fit',
            ('0781', '5591'): 'SanDisk Ultra Flair',
            # Kingston devices
            ('0951', '1666'): 'Kingston DataTraveler',
            ('0951', '1665'): 'Kingston Digital DataTraveler',
            ('0951', '1643'): 'Kingston DataTraveler G3',
            # Lexar devices
            ('05dc', '1234'): 'Lexar JumpDrive',
            ('05dc', 'ba02'): 'Lexar Echo ZE',
            # PNY devices
            ('154b', '007a'): 'PNY USB Flash Drive',
            ('154b', '0010'): 'PNY Attaché',
            # Corsair devices
            ('1b1c', '1a90'): 'Corsair Flash Voyager',
            ('1b1c', '1a0e'): 'Corsair Flash Survivor',
            # Generic mass storage
            ('0930', '6545'): 'Toshiba USB Drive',
            ('058f', '6387'): 'Generic USB Drive',
            ('13fe', '4200'): 'Generic Mass Storage',
            # Apple devices (could be malicious O.MG cables)
            ('05ac', '12ab'): 'Apple USB-C Charge Cable',
            ('05ac', '1460'): 'Apple Lightning to USB Cable'
        }
        
        # Tracking
        self.keystroke_buffer = deque(maxlen=1000)
        self.file_operation_tracker = defaultdict(list)
        self.process_tracker = defaultdict(list)
    
    def init_hash_database(self):
        """Initialize connection to malware hash database"""
        try:
            if os.path.exists(self.hash_db_path):
                self.hash_db_conn = sqlite3.connect(self.hash_db_path, check_same_thread=False)
                self.hash_db_conn.row_factory = sqlite3.Row  # Enable dict-like access
                logger.info(f"✅ Connected to malware hash database: {self.hash_db_path}")
                
                # Test connection and get stats
                cursor = self.hash_db_conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM malware_hashes')
                count = cursor.fetchone()[0]
                logger.info(f"📊 Malware hash database contains {count} signatures")
            else:
                logger.warning(f"⚠️ Malware hash database not found: {self.hash_db_path}")
                self.hash_db_conn = None
        except Exception as e:
            logger.error(f"❌ Failed to initialize hash database: {e}")
            self.hash_db_conn = None
    
    def calculate_file_hashes(self, file_path):
        """Calculate SHA256 and MD5 hashes for a file"""
        try:
            sha256_hash = hashlib.sha256()
            md5_hash = hashlib.md5()
            
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                while chunk := f.read(8192):
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
            
            return {
                'sha256': sha256_hash.hexdigest(),
                'md5': md5_hash.hexdigest(),
                'file_size': os.path.getsize(file_path)
            }
        except Exception as e:
            logger.debug(f"Error calculating hashes for {file_path}: {e}")
            return None
    
    def lookup_malware_hash(self, sha256_hash=None, md5_hash=None):
        """
        Lookup hash in malware database and return malware information.
        
        Returns detailed malware information if hash is found, None otherwise.
        """
        if not self.hash_db_conn:
            return None
            
        try:
            cursor = self.hash_db_conn.cursor()
            
            # Try SHA256 first (preferred)
            if sha256_hash:
                cursor.execute('''
                    SELECT * FROM malware_hashes 
                    WHERE sha256_hash = ? 
                    LIMIT 1
                ''', (sha256_hash,))
                result = cursor.fetchone()
                if result:
                    return dict(result)
            
            # Fall back to MD5 if no SHA256 match
            if md5_hash and not sha256_hash:
                cursor.execute('''
                    SELECT * FROM malware_hashes 
                    WHERE md5_hash = ? 
                    LIMIT 1
                ''', (md5_hash,))
                result = cursor.fetchone()
                if result:
                    return dict(result)
                    
            return None
            
        except Exception as e:
            logger.error(f"Error looking up hash in database: {e}")
            return None
    
    def analyze_file_for_malware(self, file_path, filename):
        """
        Analyze a file for known malware by calculating and checking hashes.
        
        Returns tuple: (is_malware, malware_info, file_hashes)
        """
        # Calculate file hashes
        file_hashes = self.calculate_file_hashes(file_path)
        if not file_hashes:
            return False, None, None
            
        # Lookup in malware database
        malware_info = self.lookup_malware_hash(
            sha256_hash=file_hashes['sha256'],
            md5_hash=file_hashes['md5']
        )
        
        if malware_info:
            logger.warning(f"🚨 MALWARE DETECTED: {filename}")
            logger.warning(f"   Family: {malware_info['malware_family']}")
            logger.warning(f"   Type: {malware_info['threat_type']}")
            logger.warning(f"   Severity: {malware_info['severity']}/10")
            logger.warning(f"   SHA256: {file_hashes['sha256']}")
            
            return True, malware_info, file_hashes
        
        return False, None, file_hashes
    
    def is_storage_device(self, device):
        """
        Determine if a USB device is a mass storage device.
        
        Uses multiple detection methods:
        1. Known VID/PID combinations
        2. USB interface class analysis
        3. Device class inspection
        """
        vid = device.get('vid', '').lower()
        pid = device.get('pid', '').lower()
        
        # Method 1: Check against known storage device database
        if (vid, pid) in self.known_storage_devices:
            device_name = self.known_storage_devices[(vid, pid)]
            logger.debug(f"Identified storage device: {device_name} ({vid}:{pid})")
            return True
        
        # Method 2: Check USB interface class for mass storage
        device_class = device.get('class', '').lower()
        if 'mass storage' in device_class:
            logger.debug(f"Device identified as mass storage by class: {device_class}")
            return True
            
        # Method 3: Check if device has storage flag already set
        if device.get('storage', False):
            return True
            
        # Method 4: Check for common storage device characteristics
        product = device.get('product', '').lower()
        storage_keywords = ['flash', 'drive', 'storage', 'disk', 'stick', 'cruzer', 'traveler', 'ultra']
        if any(keyword in product for keyword in storage_keywords):
            logger.debug(f"Device identified as storage by product name: {product}")
            return True
            
        return False

    def validate_mount_point(self, mount_point, depth_preference=True):
        """
        Validate and score a potential mount point.

        Returns a tuple (is_valid, score) where higher score = better mount point.
        Score factors: exists (1), is actual mount (10), has files (5), path depth (1 per level)
        Empty directories are rejected (score=0).
        """
        if not mount_point or not os.path.exists(mount_point):
            logger.debug(f"✗ {mount_point} does not exist - rejected")
            return False, 0

        score = 1  # Exists
        file_count = 0

        # Check if directory has files - REJECT empty directories
        try:
            files = os.listdir(mount_point)
            file_count = len(files)
            if file_count > 0:
                score += 5  # Increased from 1 to 5
                logger.debug(f"✓ {mount_point} has {file_count} files (+5)")
            else:
                logger.debug(f"✗ {mount_point} is EMPTY (0 files) - REJECTED")
                return False, 0  # Reject empty directories
        except Exception as e:
            logger.debug(f"✗ {mount_point} cannot read directory: {e} - rejected")
            return False, 0

        # Check if it's an actual mount point - HIGHEST WEIGHT
        is_mount = False
        try:
            if os.path.ismount(mount_point):
                is_mount = True
                score += 10  # Increased from 2 to 10
                logger.debug(f"✓ {mount_point} is an ACTUAL MOUNT POINT (+10)")
            else:
                logger.debug(f"  {mount_point} is NOT a mount point (directory only)")
        except Exception as e:
            logger.debug(f"  {mount_point} ismount check failed: {e}")

        # Prefer deeper paths (tie-breaker)
        if depth_preference:
            depth = mount_point.count(os.sep)
            score += depth
            logger.debug(f"✓ {mount_point} depth={depth} (+{depth})")

        logger.info(f"📊 Mount validation: {mount_point} -> score={score} (mount={is_mount}, files={file_count})")
        return True, score

    def find_mount_point_for_device(self, device):
        """
        Find the mount point for a USB storage device using multiple methods.

        Collects all candidate mount points and returns the best one based on validation scoring.
        Returns the mount point path if found, None otherwise.
        """
        candidates = {}  # {mount_point: score}

        try:
            vid = device.get('vid', '').lower()
            pid = device.get('pid', '').lower()
            serial = device.get('serial', '')
            devpath = device.get('devpath', '')

            logger.info(f"🔍 [MOUNT SEARCH] Searching for mount point: VID={vid}, PID={pid}")

            # Read /proc/mounts once for verification
            actual_mounts = set()
            try:
                with open('/proc/mounts', 'r') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2:
                            actual_mounts.add(parts[1])  # Add mount point path
                logger.debug(f"[MOUNT VERIFY] Loaded {len(actual_mounts)} actual mounts from /proc/mounts")
            except Exception as e:
                logger.warning(f"[MOUNT VERIFY] Could not read /proc/mounts: {e}")

            # Helper to check if path is in actual mounts
            def is_in_proc_mounts(path):
                in_mounts = path in actual_mounts
                if not in_mounts:
                    logger.debug(f"[MOUNT VERIFY] ✗ {path} NOT in /proc/mounts - may be directory only")
                else:
                    logger.debug(f"[MOUNT VERIFY] ✓ {path} confirmed in /proc/mounts")
                return in_mounts

            # Method 1: Use udevadm to find the block device for this USB device
            if devpath:
                try:
                    logger.debug(f"[MOUNT METHOD 1] Trying udevadm with devpath={devpath}")
                    # Find block devices associated with this USB device
                    result = subprocess.run(
                        ['udevadm', 'info', '--query=all', '--path=' + devpath],
                        capture_output=True, text=True, timeout=5
                    )

                    # Look for DEVNAME in the output - look for partitions (sda1) not just devices (sda)
                    for line in result.stdout.split('\n'):
                        if 'DEVNAME=' in line and '/dev/sd' in line:
                            block_device = line.split('DEVNAME=')[1].strip()
                            logger.debug(f"[MOUNT METHOD 1] Found block device: {block_device}")

                            # Find mount point for this block device
                            with open('/proc/mounts', 'r') as f:
                                for mount_line in f:
                                    if block_device in mount_line:
                                        parts = mount_line.split()
                                        if len(parts) >= 2:
                                            mount_point = parts[1]
                                            is_in_proc_mounts(mount_point)  # Log verification
                                            is_valid, score = self.validate_mount_point(mount_point)
                                            if is_valid:
                                                candidates[mount_point] = score
                                                logger.info(f"[MOUNT METHOD 1] ✅ Candidate: {mount_point} (score={score})")
                except Exception as e:
                    logger.debug(f"[MOUNT METHOD 1] Failed: {e}")

            # Method 2: Check /proc/mounts for USB mounts - collect ALL candidates
            try:
                logger.debug(f"[MOUNT METHOD 2] Checking /proc/mounts")
                with open('/proc/mounts', 'r') as f:
                    for line in f:
                        if ('/media/' in line or '/mnt/' in line) and ('/dev/sd' in line or '/dev/disk/' in line):
                            parts = line.split()
                            if len(parts) >= 2:
                                mount_point = parts[1]
                                is_valid, score = self.validate_mount_point(mount_point)
                                if is_valid:
                                    candidates[mount_point] = score
                                    logger.debug(f"[MOUNT METHOD 2] Candidate: {mount_point} (score={score})")
            except Exception as e:
                logger.debug(f"[MOUNT METHOD 2] Failed: {e}")

            # Method 3: Use lsblk to find mounted USB devices
            try:
                logger.debug(f"[MOUNT METHOD 3] Trying lsblk")
                result = subprocess.run(
                    ['lsblk', '-o', 'NAME,MOUNTPOINT,LABEL,TYPE', '-J'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    import json
                    lsblk_data = json.loads(result.stdout)
                    for device_entry in lsblk_data.get('blockdevices', []):
                        # Check partitions for mount points
                        for child in device_entry.get('children', []):
                            if child.get('mountpoint') and child.get('type') == 'part':
                                mount_point = child['mountpoint']
                                if '/media/' in mount_point or '/mnt/' in mount_point:
                                    is_in_proc_mounts(mount_point)  # Log verification
                                    is_valid, score = self.validate_mount_point(mount_point)
                                    if is_valid:
                                        candidates[mount_point] = score
                                        logger.info(f"[MOUNT METHOD 3] ✅ Candidate: {mount_point} (score={score})")
            except Exception as e:
                logger.debug(f"[MOUNT METHOD 3] Failed: {e}")

            # Method 4: Common mount patterns (last resort - includes non-mount directories)
            try:
                logger.debug(f"[MOUNT METHOD 4] Trying glob patterns")
                import glob
                common_mount_patterns = [
                    f"/media/burner/*",
                    f"/mnt/*",
                    f"/media/*"
                ]

                for pattern in common_mount_patterns:
                    for mount_point in glob.glob(pattern):
                        is_in_proc_mounts(mount_point)  # Log verification
                        is_valid, score = self.validate_mount_point(mount_point)
                        if is_valid:
                            candidates[mount_point] = score
                            logger.debug(f"[MOUNT METHOD 4] Candidate: {mount_point} (score={score})")
            except Exception as e:
                logger.debug(f"[MOUNT METHOD 4] Failed: {e}")

            # Select the best mount point (highest score)
            if candidates:
                best_mount = max(candidates.items(), key=lambda x: x[1])
                logger.info(f"🎯 [MOUNT RESULT] Selected BEST mount: {best_mount[0]} (score={best_mount[1]} from {len(candidates)} candidates)")
                return best_mount[0]
            else:
                logger.warning(f"⚠️ [MOUNT RESULT] No valid mount points found")
                return None

        except Exception as e:
            logger.error(f"❌ [MOUNT ERROR] Error finding mount point: {e}")

        return None
        
    def monitor_usb_events(self):
        """Monitor USB device insertions/removals"""
        observer = pyudev.MonitorObserver(self.monitor, self.handle_usb_event)
        observer.start()
        return observer
    
    def handle_usb_event(self, action, device):
        """Handle USB device events"""
        try:
            if action == 'add':
                logger.info(f"🔌 USB device connected: {device.get('ID_MODEL', 'Unknown')}")
                self.analyze_usb_device_with_retry(device)
            elif action == 'remove':
                logger.info(f"🔌 USB device removed: {device.get('ID_MODEL', 'Unknown')}")

        except Exception as e:
            logger.error(f"Error handling USB event: {e}")
    
    def get_usb_devices(self):
        """Get all currently connected USB devices"""
        devices = []
        
        try:
            # Method 1: lsusb
            result = subprocess.run(['lsusb', '-v'], 
                                  capture_output=True, text=True, timeout=10)
            devices.extend(self.parse_lsusb_output(result.stdout))
            
            # Method 2: udev
            for device in self.context.list_devices(subsystem='usb'):
                if device.get('ID_VENDOR_ID') and device.get('ID_MODEL_ID'):
                    devices.append({
                        'vid': device.get('ID_VENDOR_ID', ''),
                        'pid': device.get('ID_MODEL_ID', ''),
                        'vendor': device.get('ID_VENDOR', ''),
                        'product': device.get('ID_MODEL', ''),
                        'serial': device.get('ID_SERIAL_SHORT', ''),
                        'devpath': device.get('DEVPATH', ''),
                        'driver': device.get('DRIVER', ''),
                        'timestamp': datetime.utcnow().isoformat()
                    })
            
            # Deduplicate
            unique = {}
            for dev in devices:
                key = f"{dev.get('vid', '')}:{dev.get('pid', '')}:{dev.get('serial', '')}"
                if key not in unique:
                    unique[key] = dev
                    
            return list(unique.values())
            
        except Exception as e:
            logger.error(f"Error getting USB devices: {e}")
            return []
    
    def parse_lsusb_output(self, output):
        """Parse lsusb -v output"""
        devices = []
        current_device = None
        
        for line in output.split('\n'):
            if 'Bus' in line and 'Device' in line and 'ID' in line:
                # Save previous device
                if current_device:
                    devices.append(current_device)
                
                # Parse: Bus 001 Device 002: ID 0483:5740 STMicroelectronics
                match = re.search(r'ID ([0-9a-f]{4}):([0-9a-f]{4})\s+(.*)', line)
                if match:
                    current_device = {
                        'vid': match.group(1),
                        'pid': match.group(2),
                        'vendor': match.group(3).split()[0] if match.group(3) else '',
                        'timestamp': datetime.utcnow().isoformat()
                    }
            elif current_device:
                if 'iProduct' in line:
                    current_device['product'] = line.split('iProduct')[1].strip()
                elif 'iSerial' in line:
                    current_device['serial'] = line.split('iSerial')[1].strip()
                elif 'bDeviceClass' in line:
                    current_device['class'] = line.split('bDeviceClass')[1].strip()
                elif 'bInterfaceClass' in line and 'Human Interface Device' in line:
                    current_device['hid'] = True
                elif 'bInterfaceClass' in line and 'Mass Storage' in line:
                    current_device['storage'] = True
        
        if current_device:
            devices.append(current_device)
            
        return devices
    
    def monitor_hid_keystrokes(self):
        """Monitor HID devices for keystroke injection"""
        try:
            # Find HID devices
            hid_devices = []
            for event in os.listdir('/dev/input/'):
                if event.startswith('event'):
                    hid_devices.append(f'/dev/input/{event}')
            
            for device in hid_devices:
                try:
                    # Read event data (non-blocking)
                    with open(device, 'rb') as f:
                        # Set non-blocking
                        import fcntl
                        fcntl.fcntl(f, fcntl.F_SETFL, os.O_NONBLOCK)
                        
                        while True:
                            try:
                                data = f.read(24)  # Input event struct size
                                if data:
                                    # Parse input event
                                    timestamp, _, type_, code, value = struct.unpack('llHHI', data)
                                    
                                    # Type 1 = EV_KEY (keyboard)
                                    if type_ == 1 and value == 1:  # Key press
                                        self.keystroke_buffer.append({
                                            'timestamp': timestamp,
                                            'code': code,
                                            'device': device
                                        })
                            except BlockingIOError:
                                break
                except Exception:
                    pass
                    
        except Exception as e:
            logger.debug(f"HID monitoring error: {e}")
    
    def analyze_keystroke_timing(self):
        """
        Analyze keystroke timing for BadUSB detection.
        
        BadUSB devices typically type at superhuman speeds (< 10ms between keystrokes)
        because they are programmed scripts, not human typing. This is a strong indicator
        of automated keystroke injection attacks.
        """
        if len(self.keystroke_buffer) < 10:
            return 0.0
        
        # Calculate inter-keystroke delays
        delays = []
        prev_time = None
        
        for event in self.keystroke_buffer:
            if prev_time:
                delay = event['timestamp'] - prev_time
                delays.append(delay)
            prev_time = event['timestamp']
        
        if not delays:
            return 0.0
        
        avg_delay = sum(delays) / len(delays)
        
        # Superhuman typing speed (< 10ms average) - Strong BadUSB indicator
        if avg_delay < 0.01:
            logger.warning("🚨 Superhuman typing speed detected - likely BadUSB")
            return 0.9
        # Very fast but possible (10-50ms) - Suspicious but could be legitimate
        elif avg_delay < 0.05:
            return 0.6
        # Fast typing (50-100ms) - Fast but human-possible
        elif avg_delay < 0.1:
            return 0.3
        
        return 0.0
    
    def check_badusb_signatures(self, device):
        """
        Check for known BadUSB device signatures.
        
        BadUSB devices often use specific microcontroller VID/PID combinations
        that are commonly used in DIY hardware projects and attack tools.
        """
        score = 0.0
        vid = device.get('vid', '').lower()
        pid = device.get('pid', '').lower()
        product = device.get('product', '').lower()
        
        for badusb_type, info in self.badusb_signatures.items():
            # Check VID/PID pairs
            if 'vid_pid' in info:
                for known_vid, known_pid in info['vid_pid']:
                    if vid == known_vid and pid == known_pid:
                        score = max(score, info['score'])
                        logger.warning(f"🚨 BadUSB detected: {badusb_type} ({vid}:{pid})")
                        return score
            
            # Check product strings
            if 'product_strings' in info:
                for pattern in info['product_strings']:
                    if pattern.lower() in product:
                        score = max(score, info['score'] * 0.8)
                        logger.warning(f"⚠️ Suspicious product name: {product}")
        
        return score
    
    def monitor_usb_events(self):
        """
        Monitor USB device insertion and removal events with enhanced storage detection.
        
        This method starts a USB event monitor that detects when devices are plugged/unplugged
        and automatically identifies storage devices to ensure malware detection runs consistently.
        """
        import pyudev
        import threading
        import time
        
        def usb_event_handler(action, device):
            """Handle USB device events with proper storage identification"""
            try:
                if action in ['add', 'remove']:
                    # Only process main USB devices, skip interfaces and other sub-devices
                    devtype = device.get('DEVTYPE', '')
                    if devtype != 'usb_device':
                        logger.debug(f"Skipping USB event for {devtype} device")
                        return
                    # Extract device information with multiple attribute fallbacks
                    device_info = {
                        'vid': (device.get('ID_VENDOR_ID') or device.get('idVendor') or '').lower(),
                        'pid': (device.get('ID_MODEL_ID') or device.get('idProduct') or '').lower(),
                        'vendor': device.get('ID_VENDOR') or device.get('manufacturer') or 'Unknown',
                        'product': device.get('ID_MODEL') or device.get('product') or 'Unknown',
                        'serial': device.get('ID_SERIAL_SHORT') or device.get('serial') or '',
                        'class': device.get('ID_USB_CLASS_FROM_DATABASE') or device.get('bDeviceClass') or '',
                        'devpath': device.device_path or '',
                        'devnode': device.device_node or '',
                        'devtype': device.get('DEVTYPE', ''),
                        'subsystem': device.get('SUBSYSTEM', '')
                    }
                    
                    # Critical fix: Identify storage devices during events
                    device_info['storage'] = self.is_storage_device(device_info)
                    device_info['hid'] = 'HID' in device_info.get('class', '').upper()
                    
                    # Log the event with enhanced debugging
                    if action == 'add':
                        logger.info(f"🔌 USB device connected: {device_info['product']}")
                        logger.debug(f"USB event device info: VID={device_info['vid']}, PID={device_info['pid']}, Storage={device_info['storage']}")
                        logger.debug(f"Device attributes: {dict(device.items())}")
                        
                        # Special check for SanDisk Cruzer Glide and other known storage devices
                        if device_info['vid'] == '0781' and device_info['pid'] == '5575':
                            logger.info(f"✅ Detected SanDisk Cruzer Glide - forcing storage analysis")
                            device_info['storage'] = True
                        elif device_info['storage']:
                            logger.info(f"✅ Detected storage device {device_info['product']} - will analyze files")

                        # Check if this device was already analyzed recently (prevent duplicates)
                        device_key = f"{device_info['vid']}:{device_info['pid']}:{device_info['serial']}"
                        current_time = time.time()

                        if not hasattr(self, 'recent_analyses'):
                            self.recent_analyses = {}

                        # Only analyze if not analyzed in last 10 seconds
                        if device_key not in self.recent_analyses or (current_time - self.recent_analyses[device_key]) > 10:
                            logger.debug(f"Analyzing USB device: {device_info}")
                            self.recent_analyses[device_key] = current_time
                            # Use retry wrapper for consistent mount detection
                            self.analyze_usb_device_with_retry(device_info)
                        else:
                            logger.debug(f"Skipping duplicate analysis for {device_key}")
                        
                    elif action == 'remove':
                        logger.info(f"🔌 USB device removed: {device_info['product']}")
                        
            except Exception as e:
                logger.error(f"USB event handling error: {e}")
                logger.debug(f"USB event details - Action: {action}, Device: {device}")
        
        try:
            # Set up pyudev context and monitor
            context = pyudev.Context()
            monitor = pyudev.Monitor.from_netlink(context)
            
            # Monitor USB subsystem events
            monitor.filter_by('usb')
            
            # Start monitoring in a separate thread  
            observer = pyudev.MonitorObserver(monitor, usb_event_handler)
            observer.start()
            
            logger.info("✅ USB event monitoring started")
            logger.debug(f"USB monitor filtering subsystem: usb")
            
            # Test event capture by logging all existing USB devices
            logger.debug("Current USB devices:")
            for device in context.list_devices(subsystem='usb'):
                if device.get('DEVTYPE') == 'usb_device':
                    vid = device.get('ID_VENDOR_ID', '')
                    pid = device.get('ID_MODEL_ID', '')
                    logger.debug(f"  USB device: {vid}:{pid} - {device.get('ID_MODEL', 'Unknown')}")
            
            return observer
            
        except Exception as e:
            logger.error(f"Failed to start USB event monitoring: {e}")
            logger.error(f"pyudev error details: {str(e)}")
            return None
    
    def check_malicious_behaviors(self, device):
        """
        Check for malicious USB behaviors with detailed explanations.
        
        This function analyzes various behavioral indicators that suggest
        a USB device is being used for malicious purposes.
        """
        logger.debug(f"🔍 ENTERING check_malicious_behaviors for device: {device.get('product', 'Unknown')}")
        logger.debug(f"🔍 Device VID/PID: {device.get('vid', 'N/A')}:{device.get('pid', 'N/A')}")
        logger.debug(f"🔍 Device storage flag: {device.get('storage', False)}")
        
        score = 0.0
        threat_details = []
        
        # Check for known attack device VID/PID
        vid_pid = (device.get('vid', '').lower(), device.get('pid', '').lower())
        if vid_pid in self.known_attack_devices:
            attack_info = self.known_attack_devices[vid_pid]
            score = max(score, attack_info['score'])
            threat_details.append(attack_info['description'])
            logger.warning(f"🚨 {attack_info['name']} detected: {vid_pid}")
        
        # Check keystroke injection
        keystroke_score = self.analyze_keystroke_timing()
        if keystroke_score > 0.5:
            score = max(score, keystroke_score)
            threat_details.append(f"Superhuman typing speed detected (<10ms between keystrokes) - Likely automated keystroke injection attack from BadUSB/Rubber Ducky")
        
        # Check for suspicious file operations
        # Enhanced storage detection: Check multiple conditions to ensure file analysis runs
        storage_flag = device.get('storage', False)
        storage_check = self.is_storage_device(device)
        attack_device = vid_pid == ('048d', '1167')  # Known attack device
        cruzer_glide = vid_pid == ('0781', '5575')   # SanDisk Cruzer Glide
        
        is_storage_device = storage_flag or storage_check or attack_device or cruzer_glide
        
        logger.debug(f"🔍 Storage detection - Flag: {storage_flag}, Check: {storage_check}, Attack: {attack_device}, Cruzer: {cruzer_glide}")
        logger.debug(f"🔍 Final storage decision: {is_storage_device}")
        
        if is_storage_device:
            logger.info(f"📁 RUNNING FILE ANALYSIS for {device.get('product', 'Unknown')} (VID/PID: {vid_pid[0]}:{vid_pid[1]})")
            # Ensure storage flag is set for subsequent processing
            device['storage'] = True
            file_score, file_threats = self.check_suspicious_files(device, device.get('mount_point'))
            logger.info(f"📁 FILE ANALYSIS COMPLETE - Score: {file_score}, Threats: {len(file_threats)}")
            score = max(score, file_score)
            threat_details.extend(file_threats)
        else:
            logger.debug(f"🔍 No file analysis - not detected as storage device")
        
        # Check for dual-function devices (HID + Storage)
        if device.get('hid') and device.get('storage'):
            score = max(score, 0.7)
            threat_details.append("Dual-function USB device (HID + Storage) - Suspicious combination often used by BadUSB devices to both type commands and store payloads")
            logger.warning("⚠️ Dual-function USB device detected")
        
        # Check for devices without proper descriptors
        if not device.get('product') or device.get('product') == 'Unknown':
            score = max(score, 0.6)
            threat_details.append("USB device missing vendor/product descriptors - Legitimate devices identify themselves properly. This could be a BadUSB or device attempting to avoid detection")
        
        # Check for spoofed Apple/trusted devices
        if device.get('vid') == '05ac':  # Apple
            if 'apple' not in device.get('vendor', '').lower():
                score = max(score, 0.8)
                threat_details.append("Spoofed Apple device detected - VID claims to be Apple but vendor string doesn't match. Possible O.MG cable or malicious device")
                logger.warning("🚨 Spoofed Apple device detected")
        
        logger.debug(f"🔍 EXITING check_malicious_behaviors - Final score: {score}, Threats: {len(threat_details)}")
        logger.debug(f"🔍 Threat details: {threat_details[:3] if threat_details else 'None'}")
        
        return score, threat_details
    
    def check_suspicious_files(self, device, mount_point=None):
        """
        Check for suspicious files on USB storage with enhanced threat analysis.
        
        Advanced analysis including autorun files, double extensions, attack patterns,
        and sophisticated malware detection techniques.
        """
        score = 0.0
        threat_details = []
        
        try:
            logger.debug(f"🔍 ENTERING check_suspicious_files for {device.get('product', 'Unknown')}")
            # Find mount point if not provided
            if not mount_point:
                logger.debug("🔍 Searching for mount point...")
                result = subprocess.run(['mount'], capture_output=True, text=True)
                
                for line in result.stdout.split('\n'):
                    if '/dev/sd' in line and '/media' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            mount_point = parts[2]
                            logger.debug(f"🔍 Found mount point: {mount_point}")
                            break
            
            if not mount_point:
                logger.warning(f"🔍 NO MOUNT POINT FOUND for {device.get('product', 'Unknown')} - cannot analyze files")
                return score, threat_details
            else:
                logger.info(f"🔍 Using mount point: {mount_point}")
            
            # Check volume label
            volume_label = os.path.basename(mount_point)
            for pattern in self.suspicious_volume_labels:
                if re.match(pattern, volume_label, re.IGNORECASE):
                    score = max(score, 0.7)
                    threat_details.append(f"USB volume labeled '{volume_label}' - Name associated with penetration testing/attack tools")
                    logger.warning(f"🚨 Suspicious USB volume label: {volume_label}")
                    break
            
            # Enhanced autorun file detection
            autorun_score, autorun_threats = self.analyze_autorun_files(mount_point)
            score = max(score, autorun_score)
            threat_details.extend(autorun_threats)
            
            # Double extension and masquerading detection
            masq_score, masq_threats = self.detect_file_masquerading(mount_point)
            score = max(score, masq_score)
            threat_details.extend(masq_threats)
            
            # Common attack pattern detection
            pattern_score, pattern_threats = self.detect_attack_patterns(mount_point)
            score = max(score, pattern_score)
            threat_details.extend(pattern_threats)
            
            # Advanced file analysis
            analysis_score, analysis_threats = self.analyze_file_characteristics(mount_point)
            score = max(score, analysis_score)
            threat_details.extend(analysis_threats)
            
            # Document exploit detection
            doc_score, doc_threats = self.detect_document_exploits(mount_point)
            score = max(score, doc_score)
            threat_details.extend(doc_threats)
            
            # Living-off-the-land technique detection
            lol_score, lol_threats = self.detect_living_off_land_techniques(mount_point)
            score = max(score, lol_score)
            threat_details.extend(lol_threats)
            
            # Enhanced file analysis with hash checking
            exe_found = []
            suspicious_found = []
            malware_found = []
            
            for root, dirs, files in os.walk(mount_point):
                # Don't traverse too deep
                if root.count(os.sep) - mount_point.count(os.sep) > 2:
                    continue
                    
                for file in files:
                    file_path = os.path.join(root, file)
                    file_lower = file.lower()
                    
                    # Check for executable files and analyze them
                    is_executable = any(file.endswith(ext) for ext in self.malicious_behaviors['autorun_abuse']['executables'])
                    
                    if is_executable:
                        exe_found.append(file)
                        if len(exe_found) <= 3:  # Only log first few
                            logger.warning(f"⚠️ Executable on USB: {file}")
                        
                        # Hash-based malware detection for executables
                        try:
                            is_malware, malware_info, file_hashes = self.analyze_file_for_malware(file_path, file)
                            if is_malware and malware_info:
                                score = max(score, 0.98)  # Very high score for known malware
                                malware_found.append({
                                    'filename': file,
                                    'malware_info': malware_info,
                                    'hashes': file_hashes
                                })
                                threat_details.append(f"🚨 KNOWN MALWARE: '{file}' - {malware_info['malware_family']} ({malware_info['threat_type']}) - Severity {malware_info['severity']}/10")
                                
                        except Exception as e:
                            logger.debug(f"Error analyzing file {file} for malware: {e}")
                    
                    # Enhanced suspicious names detection
                    suspicious_names = ['mimikatz', 'lazagne', 'empire', 'meterpreter', 
                                      'sgportable', 'payload', 'exploit', 'pwn', 'cobalt',
                                      'beacon', 'metasploit', 'shellcode', 'backdoor',
                                      'keylogger', 'stealer', 'trojan', 'ransomware']
                    for sus_name in suspicious_names:
                        if sus_name in file_lower:
                            suspicious_found.append(file)
                            score = max(score, 0.85)
                            logger.warning(f"🚨 Suspicious file detected: {file}")
            
            # Update threat reporting based on findings
            if malware_found:
                malware_families = list(set([m['malware_info']['malware_family'] for m in malware_found]))
                threat_details.append(f"CRITICAL: {len(malware_found)} known malware files detected - Families: {', '.join(malware_families[:3])}")
                
            elif exe_found:
                if len(exe_found) > 5:
                    score = max(score, 0.8)
                    threat_details.append(f"USB contains {len(exe_found)} executable files - High risk of malware/tools. Files include: {', '.join(exe_found[:3])}...")
                else:
                    score = max(score, 0.6)
                    threat_details.append(f"USB contains executable files: {', '.join(exe_found)} - Potential security risk")
            
            if suspicious_found:
                threat_details.append(f"Known attack tool names detected: {', '.join(suspicious_found[:3])} - Common penetration testing/malware tools")
                            
        except Exception as e:
            logger.debug(f"File check error: {e}")
            
        return score, threat_details
    
    def analyze_autorun_files(self, mount_point):
        """
        Advanced autorun file analysis with comprehensive parsing and threat detection.
        
        Analyzes autorun.inf, desktop.ini, and other auto-execution files for malicious content.
        """
        score = 0.0
        threats = []
        
        try:
            # Enhanced autorun.inf analysis
            autorun_path = os.path.join(mount_point, 'autorun.inf')
            if os.path.exists(autorun_path):
                try:
                    with open(autorun_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    # Parse autorun.inf sections
                    autorun_analysis = self.parse_autorun_content(content)
                    
                    if autorun_analysis['executable_refs']:
                        score = max(score, 0.95)
                        threats.append(f"Autorun.inf references executables: {', '.join(autorun_analysis['executable_refs'][:3])} - Classic malware auto-execution technique")
                        
                    if autorun_analysis['suspicious_commands']:
                        score = max(score, 0.9)
                        threats.append(f"Autorun.inf contains suspicious commands: {', '.join(autorun_analysis['suspicious_commands'][:2])} - Potential command injection")
                        
                    if autorun_analysis['hidden_sections']:
                        score = max(score, 0.8)
                        threats.append(f"Autorun.inf has hidden/obfuscated sections - Evasion technique commonly used by malware")
                        
                    logger.warning(f"🚨 AUTORUN ANALYSIS: {len(autorun_analysis['executable_refs'])} executables, {len(autorun_analysis['suspicious_commands'])} suspicious commands")
                        
                except Exception as e:
                    score = max(score, 0.7)
                    threats.append(f"Autorun.inf present but unreadable - Potential binary/corrupted autorun file used for evasion")
                    logger.warning(f"⚠️ Autorun.inf read error: {e}")
            
            # Desktop.ini analysis  
            desktop_ini_path = os.path.join(mount_point, 'desktop.ini')
            if os.path.exists(desktop_ini_path):
                try:
                    with open(desktop_ini_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    if 'iconresource=' in content.lower() and '.exe' in content.lower():
                        score = max(score, 0.8)
                        threats.append("Desktop.ini references executable as icon - Technique to disguise malware execution as icon loading")
                        
                    if 'shellclassinfo' in content.lower() and ('handler' in content.lower() or 'command' in content.lower()):
                        score = max(score, 0.85)
                        threats.append("Desktop.ini contains shell command handlers - Can execute arbitrary commands when folder is accessed")
                        
                except Exception:
                    score = max(score, 0.6)
                    threats.append("Desktop.ini present but unreadable - Potential obfuscated configuration file")
            
            # Check for other autorun file types
            other_autorun_files = [
                ('thumb.db', 0.7, "Thumbs.db file present - Sometimes used to hide malicious code or as decoy"),
                ('.ds_store', 0.6, "macOS .DS_Store file on Windows USB - Suspicious cross-platform artifact"),
                ('folder.htt', 0.8, "Folder.htt file present - Can contain script code that executes when folder is viewed"),
                ('shellscrap.scf', 0.9, "Shell Command File (.scf) present - Can execute commands when folder is accessed")
            ]
            
            for filename, threat_score, description in other_autorun_files:
                file_path = os.path.join(mount_point, filename)
                if os.path.exists(file_path):
                    score = max(score, threat_score)
                    threats.append(description)
                    logger.warning(f"⚠️ Autorun file detected: {filename}")
                    
        except Exception as e:
            logger.debug(f"Autorun analysis error: {e}")
            
        return score, threats
    
    def parse_autorun_content(self, content):
        """Parse autorun.inf content for detailed threat analysis"""
        analysis = {
            'executable_refs': [],
            'suspicious_commands': [],
            'hidden_sections': []
        }
        
        # Look for executable references
        exe_patterns = [
            r'open\s*=\s*([^\r\n]+\.exe[^\r\n]*)',
            r'shellexecute\s*=\s*([^\r\n]+\.exe[^\r\n]*)',
            r'icon\s*=\s*([^\r\n]+\.exe[^\r\n]*)'
        ]
        
        for pattern in exe_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            analysis['executable_refs'].extend(matches)
        
        # Look for suspicious commands
        suspicious_patterns = [
            r'(cmd\.exe[^\r\n]*)',
            r'(powershell[^\r\n]*)',
            r'(rundll32[^\r\n]*)',
            r'(regsvr32[^\r\n]*)',
            r'(wscript[^\r\n]*)',
            r'(cscript[^\r\n]*)'
        ]
        
        for pattern in suspicious_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            analysis['suspicious_commands'].extend(matches)
        
        # Look for hidden/obfuscated sections
        if re.search(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\xFF]', content):
            analysis['hidden_sections'].append("Binary/non-printable characters detected")
            
        if len(content.split('\n')) > 20:
            analysis['hidden_sections'].append("Unusually long autorun.inf file")
            
        return analysis
    
    def detect_file_masquerading(self, mount_point):
        """
        Detect file masquerading techniques including double extensions and deceptive filenames.
        
        Malware often uses double extensions like 'document.pdf.exe' to trick users
        into thinking they're opening safe files when they're actually executables.
        """
        score = 0.0
        threats = []
        
        try:
            for root, dirs, files in os.walk(mount_point):
                if root.count(os.sep) - mount_point.count(os.sep) > 3:
                    continue
                    
                for file in files:
                    file_lower = file.lower()
                    
                    # Check for double extensions
                    double_ext_patterns = [
                        r'\.pdf\.exe$', r'\.doc\.exe$', r'\.docx\.exe$', r'\.txt\.exe$',
                        r'\.jpg\.exe$', r'\.png\.exe$', r'\.gif\.exe$', r'\.mp3\.exe$',
                        r'\.mp4\.exe$', r'\.avi\.exe$', r'\.zip\.exe$', r'\.rar\.exe$',
                        r'\.pdf\.scr$', r'\.doc\.scr$', r'\.jpg\.scr$', r'\.txt\.scr$',
                        r'\.pdf\.bat$', r'\.doc\.bat$', r'\.txt\.bat$', r'\.jpg\.bat$',
                        r'\.pdf\.cmd$', r'\.doc\.cmd$', r'\.txt\.cmd$', r'\.xls\.exe$'
                    ]
                    
                    for pattern in double_ext_patterns:
                        if re.search(pattern, file_lower):
                            score = max(score, 0.9)
                            threats.append(f"Double extension file detected: '{file}' - Classic malware technique to disguise executables as documents/media")
                            logger.warning(f"🚨 DOUBLE EXTENSION: {file}")
                            break
                    
                    # Check for deceptive Unicode characters
                    if self.contains_deceptive_unicode(file):
                        score = max(score, 0.85)
                        threats.append(f"File with deceptive Unicode characters: '{file}' - May use right-to-left override or lookalike characters to hide true extension")
                        logger.warning(f"🚨 UNICODE DECEPTION: {file}")
                    
                    # Check for executable files disguised as system files
                    system_file_patterns = [
                        r'readme\.exe$', r'install\.exe$', r'setup\.exe$', r'update\.exe$',
                        r'driver\.exe$', r'codec\.exe$', r'player\.exe$', r'viewer\.exe$',
                        r'svchost\.exe$', r'explorer\.exe$', r'winlogon\.exe$', r'taskmgr\.exe$'
                    ]
                    
                    for pattern in system_file_patterns:
                        if re.search(pattern, file_lower):
                            score = max(score, 0.8)
                            threats.append(f"File mimicking system executable: '{file}' - May be malware disguised as legitimate system file")
                            logger.warning(f"⚠️ SYSTEM FILE MIMIC: {file}")
                            break
                    
                    # Check for spaces before extension (another masquerading technique)
                    if re.search(r'\s+\.(exe|scr|bat|cmd|pif|com)$', file_lower):
                        score = max(score, 0.85)
                        threats.append(f"File with spaces before extension: '{file}' - Technique to hide true file type in some file managers")
                        logger.warning(f"🚨 SPACE PADDING: {file}")
                    
                    # Check for very long filenames (possible buffer overflow attempts)
                    if len(file) > 200:
                        score = max(score, 0.7)
                        threats.append(f"Extremely long filename detected ({len(file)} chars) - Possible buffer overflow attempt or evasion technique")
                        logger.warning(f"⚠️ LONG FILENAME: {file[:50]}...")
                        
        except Exception as e:
            logger.debug(f"File masquerading detection error: {e}")
            
        return score, threats
    
    def contains_deceptive_unicode(self, filename):
        """Check for deceptive Unicode characters in filenames"""
        # Right-to-left override characters
        rtl_chars = ['\u202E', '\u202D', '\u200F', '\u200E']
        
        # Lookalike characters that could deceive
        lookalikes = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',  # Cyrillic
            'і': 'i', 'ј': 'j', 'ѕ': 's', 'у': 'y', 'А': 'A', 'В': 'B',
            'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P',
            'С': 'C', 'Т': 'T', 'Х': 'X'
        }
        
        # Check for RTL override
        for rtl_char in rtl_chars:
            if rtl_char in filename:
                return True
        
        # Check for suspicious lookalike usage
        lookalike_count = 0
        for char in filename:
            if char in lookalikes:
                lookalike_count += 1
                
        # If more than 20% of characters are lookalikes, it's suspicious
        if len(filename) > 0 and (lookalike_count / len(filename)) > 0.2:
            return True
            
        return False
    
    def detect_attack_patterns(self, mount_point):
        """
        Detect common attack patterns in file contents and structure.
        
        Analyzes files for known attack payloads, social engineering attempts,
        and malicious code patterns.
        """
        score = 0.0
        threats = []
        
        try:
            suspicious_file_count = 0
            
            for root, dirs, files in os.walk(mount_point):
                if root.count(os.sep) - mount_point.count(os.sep) > 3:
                    continue
                    
                for file in files:
                    file_path = os.path.join(root, file)
                    file_lower = file.lower()
                    
                    # Skip binary files that are too large
                    try:
                        file_size = os.path.getsize(file_path)
                        if file_size > 10 * 1024 * 1024:  # Skip files > 10MB
                            continue
                    except:
                        continue
                    
                    # Analyze text-based files for payload patterns
                    if any(file_lower.endswith(ext) for ext in ['.txt', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.py', '.sh']):
                        pattern_score, pattern_threats = self.analyze_file_content_patterns(file_path)
                        if pattern_score > 0:
                            score = max(score, pattern_score)
                            threats.extend(pattern_threats)
                            suspicious_file_count += 1
                    
                    # Check for social engineering file names
                    social_patterns = [
                        r'urgent.*update', r'security.*patch', r'virus.*scan',
                        r'password.*reset', r'account.*verify', r'click.*here',
                        r'important.*document', r'confidential.*report',
                        r'bitcoin.*wallet', r'crypto.*keys', r'free.*download'
                    ]
                    
                    for pattern in social_patterns:
                        if re.search(pattern, file_lower):
                            score = max(score, 0.7)
                            threats.append(f"Social engineering filename detected: '{file}' - Uses psychological manipulation to encourage execution")
                            logger.warning(f"⚠️ SOCIAL ENGINEERING: {file}")
                            break
                    
                    # Check for file structure manipulation
                    if file_lower.startswith('.') and not file_lower.startswith('.ds_store'):
                        score = max(score, 0.6)
                        threats.append(f"Hidden file detected: '{file}' - May be attempting to avoid detection")
                        
            if suspicious_file_count > 3:
                score = max(score, 0.8)
                threats.append(f"Multiple suspicious files detected ({suspicious_file_count}) - Indicates possible malware collection or attack toolkit")
                
        except Exception as e:
            logger.debug(f"Attack pattern detection error: {e}")
            
        return score, threats
    
    def analyze_file_content_patterns(self, file_path):
        """Analyze file content for malicious patterns"""
        score = 0.0
        threats = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(8192)  # Read first 8KB
                
            # PowerShell attack patterns
            powershell_patterns = [
                r'IEX\s*\(\s*New-Object.*DownloadString',
                r'Invoke-Expression.*DownloadString',
                r'powershell.*-enc\s+[A-Za-z0-9+/=]{20,}',
                r'System\.Net\.WebClient.*DownloadFile',
                r'-WindowStyle\s+Hidden',
                r'Invoke-Mimikatz',
                r'Invoke-Shellcode',
                r'Empire\.|PowerSploit\.'
            ]
            
            for pattern in powershell_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    score = max(score, 0.9)
                    threats.append(f"PowerShell attack pattern in {os.path.basename(file_path)} - Contains malicious PowerShell commands for code execution/download")
                    break
            
            # Command injection patterns
            cmd_patterns = [
                r'cmd\.exe.*[&|]{2}.*curl',
                r'wget.*[&|]{2}.*chmod',
                r'nc\s+-[lne]+.*\d+',
                r'/bin/bash.*-i.*>/dev/tcp',
                r'python.*-c.*socket',
                r'ruby.*-e.*TCPSocket'
            ]
            
            for pattern in cmd_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    score = max(score, 0.85)
                    threats.append(f"Command injection pattern in {os.path.basename(file_path)} - Contains commands for reverse shell or remote access")
                    break
            
            # Base64 encoded payloads
            base64_pattern = r'[A-Za-z0-9+/]{100,}={0,2}'
            base64_matches = re.findall(base64_pattern, content)
            if len(base64_matches) > 2:
                score = max(score, 0.8)
                threats.append(f"Multiple Base64 encoded strings in {os.path.basename(file_path)} - Possible encoded malicious payloads")
            
            # Registry manipulation
            if re.search(r'HKEY_.*\\.*\\.*', content, re.IGNORECASE):
                score = max(score, 0.7)
                threats.append(f"Registry manipulation detected in {os.path.basename(file_path)} - May modify system configuration for persistence")
                
        except Exception as e:
            logger.debug(f"Content analysis error for {file_path}: {e}")
            
        return score, threats
    
    def analyze_file_characteristics(self, mount_point):
        """
        Advanced file analysis including headers, entropy, and metadata.
        
        Examines file characteristics that may indicate malicious content
        such as high entropy (packed/encrypted), mismatched headers, etc.
        """
        score = 0.0
        threats = []
        
        try:
            executable_files = []
            high_entropy_files = []
            
            for root, dirs, files in os.walk(mount_point):
                if root.count(os.sep) - mount_point.count(os.sep) > 2:
                    continue
                    
                for file in files:
                    file_path = os.path.join(root, file)
                    file_lower = file.lower()
                    
                    try:
                        file_size = os.path.getsize(file_path)
                        
                        # Skip very large files for performance
                        if file_size > 50 * 1024 * 1024:
                            continue
                            
                        # Check file headers vs extensions
                        if file_size > 0:
                            header_score, header_threats = self.check_file_header_mismatch(file_path, file_lower)
                            score = max(score, header_score)
                            threats.extend(header_threats)
                            
                        # Calculate entropy for potential packing/encryption detection
                        if file_size > 1024 and file_size < 5 * 1024 * 1024:  # 1KB to 5MB
                            entropy = self.calculate_file_entropy(file_path)
                            if entropy > 7.5:  # High entropy indicates compression/encryption
                                high_entropy_files.append(file)
                                if file_lower.endswith(('.txt', '.log', '.cfg', '.ini')):
                                    # Text files shouldn't have high entropy
                                    score = max(score, 0.8)
                                    threats.append(f"High entropy text file: '{file}' - May be encrypted/packed malware disguised as text")
                                    
                        # Check for executable files with document extensions
                        if self.is_executable_file(file_path) and any(file_lower.endswith(ext) for ext in ['.pdf', '.doc', '.docx', '.txt', '.jpg', '.png']):
                            score = max(score, 0.95)
                            threats.append(f"Executable disguised as document: '{file}' - PE/ELF executable with document extension")
                            logger.warning(f"🚨 DISGUISED EXECUTABLE: {file}")
                            
                    except Exception as e:
                        logger.debug(f"File analysis error for {file}: {e}")
                        continue
            
            if len(high_entropy_files) > 5:
                score = max(score, 0.7)
                threats.append(f"Multiple high-entropy files detected ({len(high_entropy_files)}) - May indicate packed/encrypted malware collection")
                
        except Exception as e:
            logger.debug(f"File characteristics analysis error: {e}")
            
        return score, threats
    
    def check_file_header_mismatch(self, file_path, file_lower):
        """Check for mismatched file headers and extensions"""
        score = 0.0
        threats = []
        
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
                
            # Common file signature patterns
            signatures = {
                b'MZ': ['.exe', '.dll', '.sys'],  # PE executable
                b'\x7fELF': ['.so', '.bin'],      # ELF executable
                b'%PDF': ['.pdf'],               # PDF
                b'\x50\x4b\x03\x04': ['.zip', '.docx', '.xlsx'],  # ZIP/Office
                b'\xff\xd8\xff': ['.jpg', '.jpeg'],  # JPEG
                b'\x89PNG': ['.png'],            # PNG
                b'GIF8': ['.gif'],              # GIF
            }
            
            for sig, expected_exts in signatures.items():
                if header.startswith(sig):
                    # Check if file extension matches the signature
                    has_matching_ext = any(file_lower.endswith(ext) for ext in expected_exts)
                    
                    if not has_matching_ext:
                        if sig == b'MZ':  # Executable disguised as something else
                            score = max(score, 0.95)
                            threats.append(f"Windows executable with non-executable extension: {os.path.basename(file_path)} - Likely malware trying to avoid detection")
                        elif sig == b'\x7fELF':  # Linux executable
                            score = max(score, 0.9)
                            threats.append(f"Linux executable with document extension: {os.path.basename(file_path)} - Suspicious binary file")
                        else:
                            score = max(score, 0.7)
                            threats.append(f"File header mismatch: {os.path.basename(file_path)} - File type doesn't match extension")
                    break
                    
        except Exception as e:
            logger.debug(f"Header check error for {file_path}: {e}")
            
        return score, threats
    
    def calculate_file_entropy(self, file_path):
        """Calculate Shannon entropy of a file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(8192)  # Read first 8KB for performance
                
            if not data:
                return 0
                
            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
                
            # Calculate entropy
            entropy = 0
            data_len = len(data)
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * (probability.bit_length() - 1)
                    
            return entropy
            
        except Exception:
            return 0
    
    def is_executable_file(self, file_path):
        """Check if file is an executable based on header"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                
            # Check for common executable headers
            return (header.startswith(b'MZ') or      # PE executable
                   header.startswith(b'\x7fELF') or  # ELF executable
                   header.startswith(b'\xfe\xed') or # Mach-O (macOS)
                   header.startswith(b'\xce\xfa'))   # Mach-O (macOS)
                   
        except Exception:
            return False
    
    def detect_document_exploits(self, mount_point):
        """
        Detect malicious documents that may contain exploits.
        
        Analyzes Office documents, PDFs, and RTF files for suspicious characteristics
        that indicate they may contain exploits or malicious macros.
        """
        score = 0.0
        threats = []
        
        try:
            document_extensions = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.rtf']
            suspicious_docs = []
            
            for root, dirs, files in os.walk(mount_point):
                if root.count(os.sep) - mount_point.count(os.sep) > 2:
                    continue
                    
                for file in files:
                    file_path = os.path.join(root, file)
                    file_lower = file.lower()
                    
                    if any(file_lower.endswith(ext) for ext in document_extensions):
                        doc_score, doc_threats = self.analyze_document_file(file_path, file)
                        if doc_score > 0:
                            score = max(score, doc_score)
                            threats.extend(doc_threats)
                            suspicious_docs.append(file)
                    
                    # Check for suspicious document naming patterns
                    suspicious_doc_patterns = [
                        r'invoice.*\.(doc|pdf|xls)', r'receipt.*\.(doc|pdf)',
                        r'cv.*\.(doc|pdf)', r'resume.*\.(doc|pdf)',
                        r'salary.*\.(doc|xls|pdf)', r'payment.*\.(doc|xls|pdf)',
                        r'statement.*\.(doc|xls|pdf)', r'report.*\.(doc|xls|pdf)',
                        r'urgent.*\.(doc|pdf)', r'confidential.*\.(doc|pdf)'
                    ]
                    
                    for pattern in suspicious_doc_patterns:
                        if re.search(pattern, file_lower):
                            score = max(score, 0.6)
                            threats.append(f"Suspicious document name: '{file}' - Common pattern used in phishing/malware campaigns")
                            logger.warning(f"⚠️ SUSPICIOUS DOC NAME: {file}")
                            break
            
            if len(suspicious_docs) > 3:
                score = max(score, 0.75)
                threats.append(f"Multiple suspicious documents detected ({len(suspicious_docs)}) - May indicate targeted malware campaign")
                
        except Exception as e:
            logger.debug(f"Document exploit detection error: {e}")
            
        return score, threats
    
    def analyze_document_file(self, file_path, filename):
        """Analyze individual document files for malicious characteristics"""
        score = 0.0
        threats = []
        
        try:
            file_size = os.path.getsize(file_path)
            file_lower = filename.lower()
            
            # Read file header for analysis
            with open(file_path, 'rb') as f:
                header = f.read(512)  # Read first 512 bytes
                
            # PDF exploit detection
            if file_lower.endswith('.pdf'):
                pdf_score, pdf_threats = self.analyze_pdf_file(header, file_path, filename)
                score = max(score, pdf_score)
                threats.extend(pdf_threats)
                
            # Office document exploit detection
            elif any(file_lower.endswith(ext) for ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']):
                office_score, office_threats = self.analyze_office_file(header, file_path, filename)
                score = max(score, office_score)
                threats.extend(office_threats)
                
            # RTF exploit detection
            elif file_lower.endswith('.rtf'):
                rtf_score, rtf_threats = self.analyze_rtf_file(header, file_path, filename)
                score = max(score, rtf_score)
                threats.extend(rtf_threats)
            
            # General document characteristics
            if file_size < 1024:  # Very small documents are suspicious
                score = max(score, 0.7)
                threats.append(f"Unusually small document: '{filename}' ({file_size} bytes) - May be a dropper or exploit")
                
            elif file_size > 50 * 1024 * 1024:  # Very large documents
                score = max(score, 0.6)
                threats.append(f"Unusually large document: '{filename}' ({file_size // (1024*1024)} MB) - May contain embedded malware")
                
        except Exception as e:
            logger.debug(f"Document analysis error for {filename}: {e}")
            
        return score, threats
    
    def analyze_pdf_file(self, header, file_path, filename):
        """Analyze PDF files for exploits and malicious content"""
        score = 0.0
        threats = []
        
        try:
            # Check PDF header
            if not header.startswith(b'%PDF'):
                score = max(score, 0.8)
                threats.append(f"Invalid PDF header in '{filename}' - May be malware disguised as PDF")
                return score, threats
            
            # Read more of the file for analysis
            with open(file_path, 'rb') as f:
                content = f.read(8192)  # Read first 8KB
                content_str = content.decode('latin-1', errors='ignore')
                
            # Check for suspicious PDF elements
            suspicious_pdf_elements = [
                (b'/JavaScript', 0.85, "Contains JavaScript - Can execute malicious code"),
                (b'/JS', 0.85, "Contains JavaScript (short form) - Can execute malicious code"),
                (b'/Action', 0.7, "Contains actions - May auto-execute malicious behavior"),
                (b'/Launch', 0.9, "Contains launch action - Can execute external programs"),
                (b'/EmbeddedFile', 0.8, "Contains embedded files - May hide malware"),
                (b'/XFA', 0.75, "Contains XFA forms - Common exploit vector"),
                (b'/AcroForm', 0.6, "Contains forms - Potential data harvesting"),
                (b'/RichMedia', 0.8, "Contains rich media - Can embed Flash exploits"),
                (b'/OpenAction', 0.85, "Auto-executes on open - Very suspicious behavior")
            ]
            
            for element, threat_score, description in suspicious_pdf_elements:
                if element in content:
                    score = max(score, threat_score)
                    threats.append(f"PDF '{filename}': {description}")
                    
            # Check for obfuscation techniques
            if content.count(b'obj') > 50:  # Many objects could indicate obfuscation
                score = max(score, 0.7)
                threats.append(f"PDF '{filename}' has many objects ({content.count(b'obj')}) - Possible obfuscation")
                
            # Check for suspicious strings
            suspicious_strings = [
                'unescape', 'fromCharCode', 'String.fromCharCode',
                'eval(', 'shellcode', 'payload'
            ]
            
            for sus_str in suspicious_strings:
                if sus_str.encode() in content:
                    score = max(score, 0.8)
                    threats.append(f"PDF '{filename}' contains suspicious string: '{sus_str}' - Likely exploit code")
                    
        except Exception as e:
            logger.debug(f"PDF analysis error for {filename}: {e}")
            
        return score, threats
    
    def analyze_office_file(self, header, file_path, filename):
        """Analyze Microsoft Office files for macros and exploits"""
        score = 0.0
        threats = []
        
        try:
            file_lower = filename.lower()
            
            # Check for old Office format (OLE compound document)
            if header.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
                # Old format (.doc, .xls, .ppt) - more vulnerable
                score = max(score, 0.6)
                threats.append(f"Legacy Office format: '{filename}' - Older format with higher exploit risk")
                
                # Read more content to check for macros
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read(16384)  # Read first 16KB
                        
                    # Check for macro indicators
                    macro_indicators = [
                        b'VBA', b'Microsoft Visual Basic', b'Module1',
                        b'Auto_Open', b'Workbook_Open', b'Document_Open',
                        b'Shell', b'CreateObject', b'WScript',
                        b'powershell', b'cmd.exe'
                    ]
                    
                    macro_found = []
                    for indicator in macro_indicators:
                        if indicator in content:
                            macro_found.append(indicator.decode('ascii', errors='ignore'))
                            
                    if macro_found:
                        score = max(score, 0.9)
                        threats.append(f"Office document '{filename}' contains macro indicators: {', '.join(macro_found[:3])} - High risk of malicious macros")
                        
                except Exception:
                    pass
                    
            # Check for new Office format (ZIP-based)
            elif header.startswith(b'PK\x03\x04'):
                # New format (.docx, .xlsx, .pptx)
                if file_lower.endswith(('docm', 'xlsm', 'pptm')):
                    score = max(score, 0.8)
                    threats.append(f"Macro-enabled Office document: '{filename}' - Can contain malicious macros")
                    
                # Check if regular Office file contains macros (shouldn't have them)
                elif file_lower.endswith(('.docx', '.xlsx', '.pptx')):
                    try:
                        # Quick check for macro content in ZIP
                        with open(file_path, 'rb') as f:
                            content = f.read(8192)
                            if b'vbaProject' in content or b'macros/' in content:
                                score = max(score, 0.85)
                                threats.append(f"Standard Office document '{filename}' contains hidden macros - Suspicious activity")
                    except Exception:
                        pass
            else:
                score = max(score, 0.8)
                threats.append(f"Invalid Office document header: '{filename}' - May be malware disguised as Office file")
                
        except Exception as e:
            logger.debug(f"Office analysis error for {filename}: {e}")
            
        return score, threats
    
    def analyze_rtf_file(self, header, file_path, filename):
        """Analyze RTF files for exploits"""
        score = 0.0
        threats = []
        
        try:
            # Check RTF header
            if not header.startswith(b'{\\rtf'):
                score = max(score, 0.8)
                threats.append(f"Invalid RTF header in '{filename}' - May be malware disguised as RTF")
                return score, threats
            
            # Read content for analysis
            with open(file_path, 'rb') as f:
                content = f.read(16384)  # Read first 16KB
                content_str = content.decode('latin-1', errors='ignore')
                
            # Check for RTF exploit patterns
            rtf_exploits = [
                ('\\objdata', 0.85, "Contains embedded objects - Common exploit vector"),
                ('\\object', 0.8, "Contains OLE objects - Potential exploit embedding"),
                ('\\objclass Equation', 0.9, "Contains Equation Editor object - Known exploit vector (CVE-2017-11882)"),
                ('\\objupdate', 0.8, "Auto-updates objects - Suspicious behavior"),
                ('\\fromfile', 0.75, "References external files - May load malicious content"),
                ('Microsoft.Workflow', 0.9, "Contains Workflow object - Known exploit vector"),
                ('\\bin', 0.8, "Contains binary data - May embed malicious payloads")
            ]
            
            for pattern, threat_score, description in rtf_exploits:
                if pattern in content_str:
                    score = max(score, threat_score)
                    threats.append(f"RTF '{filename}': {description}")
                    
            # Check for excessive nesting or large objects (obfuscation)
            brace_count = content_str.count('{')
            if brace_count > 1000:
                score = max(score, 0.7)
                threats.append(f"RTF '{filename}' has excessive nesting ({brace_count} braces) - Possible obfuscation")
                
        except Exception as e:
            logger.debug(f"RTF analysis error for {filename}: {e}")
            
        return score, threats
    
    def detect_living_off_land_techniques(self, mount_point):
        """
        Detect living-off-the-land (LOL) techniques and abuse of legitimate tools.
        
        These techniques use legitimate system tools for malicious purposes,
        making them harder to detect but still identifiable through specific patterns.
        """
        score = 0.0
        threats = []
        
        try:
            lol_files_found = []
            
            for root, dirs, files in os.walk(mount_point):
                if root.count(os.sep) - mount_point.count(os.sep) > 3:
                    continue
                    
                for file in files:
                    file_path = os.path.join(root, file)
                    file_lower = file.lower()
                    
                    # Check for legitimate tools commonly abused by attackers
                    lol_tools = {
                        'certutil.exe': (0.8, "CertUtil - Often abused for downloading/encoding malware"),
                        'powershell.exe': (0.7, "PowerShell - Legitimate tool but common attack vector"),
                        'cmd.exe': (0.6, "Command Prompt - Basic but can be used maliciously"),
                        'rundll32.exe': (0.8, "RunDLL32 - Frequently abused for DLL injection attacks"),
                        'regsvr32.exe': (0.8, "RegSvr32 - Abused for script execution and bypass"),
                        'mshta.exe': (0.85, "MSHTA - HTML Application host, common attack vector"),
                        'wscript.exe': (0.7, "Windows Script Host - Can execute malicious scripts"),
                        'cscript.exe': (0.7, "Console Script Host - Can execute malicious scripts"),
                        'bitsadmin.exe': (0.85, "BITS Admin - Abused for persistence and downloading"),
                        'sc.exe': (0.8, "Service Controller - Can create malicious services"),
                        'schtasks.exe': (0.8, "Task Scheduler - Used for persistence mechanisms"),
                        'wmic.exe': (0.8, "WMI Command - Powerful tool often abused by attackers"),
                        'forfiles.exe': (0.75, "ForFiles - Can be used for indirect command execution"),
                        'regasm.exe': (0.8, "RegAsm - .NET assembly registration, bypass technique"),
                        'regsvcs.exe': (0.8, "RegSvcs - .NET services installation, bypass technique"),
                        'installutil.exe': (0.85, "InstallUtil - .NET installer, common bypass technique"),
                        'msbuild.exe': (0.85, "MSBuild - .NET build engine, can execute arbitrary code"),
                        'cmstp.exe': (0.9, "CMSTP - Connection Manager, UAC bypass technique"),
                        'fodhelper.exe': (0.9, "FodHelper - Features on Demand, UAC bypass"),
                        'dism.exe': (0.7, "DISM - Deployment Image Servicing, can be abused"),
                        'findstr.exe': (0.6, "FindStr - Text search utility, can be chained in attacks")
                    }
                    
                    for lol_tool, (threat_score, description) in lol_tools.items():
                        if file_lower == lol_tool:
                            score = max(score, threat_score)
                            threats.append(f"LOL technique tool: '{file}' - {description}")
                            lol_files_found.append(file)
                            logger.warning(f"⚠️ LOL TOOL: {file}")
                    
                    # Analyze script files for LOL technique patterns
                    if any(file_lower.endswith(ext) for ext in ['.bat', '.cmd', '.ps1', '.vbs', '.js']):
                        lol_script_score, lol_script_threats = self.analyze_lol_script_patterns(file_path, file)
                        score = max(score, lol_script_score)
                        threats.extend(lol_script_threats)
                    
                    # Check for renamed system binaries (masquerading)
                    if self.is_renamed_system_binary(file_path, file_lower):
                        score = max(score, 0.85)
                        threats.append(f"Renamed system binary detected: '{file}' - May be legitimate tool renamed to avoid detection")
                        logger.warning(f"🚨 RENAMED BINARY: {file}")
            
            # Multiple LOL tools indicate sophisticated attack
            if len(lol_files_found) > 3:
                score = max(score, 0.9)
                threats.append(f"Multiple LOL technique tools detected ({len(lol_files_found)}) - Indicates advanced persistent threat or sophisticated attack toolkit")
                
        except Exception as e:
            logger.debug(f"LOL technique detection error: {e}")
            
        return score, threats
    
    def analyze_lol_script_patterns(self, file_path, filename):
        """Analyze script files for living-off-the-land attack patterns"""
        score = 0.0
        threats = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(8192)  # Read first 8KB
                content_lower = content.lower()
                
            # PowerShell LOL patterns
            powershell_lol_patterns = [
                (r'start-process.*-windowstyle\s+hidden', 0.8, "Hidden process execution"),
                (r'invoke-webrequest.*-outfile', 0.85, "File download using PowerShell"),
                (r'new-object.*system\.net\.webclient', 0.85, "Web client for downloading"),
                (r'iex.*\(.*\)', 0.9, "Invoke-Expression with dynamic content"),
                (r'add-type.*-assemblyname', 0.8, "Dynamic assembly loading"),
                (r'reflection\.assembly.*load', 0.85, "Reflective assembly loading"),
                (r'-encodedcommand', 0.9, "Base64 encoded PowerShell command"),
                (r'bypass.*-executionpolicy', 0.85, "Execution policy bypass"),
                (r'wmicprocess.*create', 0.8, "WMI process creation"),
                (r'get-wmiobject.*win32_process', 0.7, "WMI process enumeration")
            ]
            
            # Batch/CMD LOL patterns
            batch_lol_patterns = [
                (r'certutil.*-urlcache.*-split.*-f', 0.9, "CertUtil download technique"),
                (r'certutil.*-decode', 0.8, "CertUtil decoding (common evasion)"),
                (r'bitsadmin.*\/transfer', 0.9, "BITS transfer for downloading"),
                (r'rundll32.*javascript', 0.9, "RunDLL32 JavaScript execution"),
                (r'rundll32.*url\.dll', 0.85, "RunDLL32 URL execution"),
                (r'regsvr32.*\/s.*\/u.*\/i', 0.9, "RegSvr32 squiblydoo technique"),
                (r'mshta.*http', 0.9, "MSHTA remote execution"),
                (r'wmic.*process.*call.*create', 0.8, "WMIC process creation"),
                (r'schtasks.*\/create.*\/tn', 0.8, "Scheduled task creation"),
                (r'sc.*create.*binpath', 0.85, "Service creation for persistence")
            ]
            
            # Check PowerShell patterns
            if filename.lower().endswith('.ps1'):
                for pattern, threat_score, description in powershell_lol_patterns:
                    if re.search(pattern, content_lower):
                        score = max(score, threat_score)
                        threats.append(f"PowerShell LOL pattern in '{filename}': {description}")
                        
            # Check Batch/CMD patterns
            elif filename.lower().endswith(('.bat', '.cmd')):
                for pattern, threat_score, description in batch_lol_patterns:
                    if re.search(pattern, content_lower):
                        score = max(score, threat_score)
                        threats.append(f"Batch LOL pattern in '{filename}': {description}")
            
            # Check for obfuscated commands (common in LOL attacks)
            if self.detect_command_obfuscation(content):
                score = max(score, 0.8)
                threats.append(f"Command obfuscation detected in '{filename}' - Common evasion technique in LOL attacks")
                
        except Exception as e:
            logger.debug(f"LOL script analysis error for {filename}: {e}")
            
        return score, threats
    
    def detect_command_obfuscation(self, content):
        """Detect various command obfuscation techniques"""
        # String concatenation obfuscation
        if re.search(r'[\'\"]\s*\+\s*[\'\"]\s*\+', content):
            return True
            
        # Environment variable obfuscation
        if re.search(r'%[a-zA-Z_]+:~\d+,\d+%', content):
            return True
            
        # Character replacement obfuscation
        if re.search(r'\.replace\s*\(\s*[\'\"]\w[\'\"],\s*[\'\"]\w[\'\"]\s*\)', content, re.IGNORECASE):
            return True
            
        # Excessive variable substitution
        if content.count('$') > 10 and len(content) < 1000:
            return True
            
        return False
    
    def is_renamed_system_binary(self, file_path, file_lower):
        """Check if a file is a renamed Windows system binary"""
        try:
            # Only check executables
            if not file_lower.endswith('.exe'):
                return False
                
            # Read PE header to check for system binary characteristics
            with open(file_path, 'rb') as f:
                header = f.read(1024)
                
            if not header.startswith(b'MZ'):
                return False
                
            # Look for Microsoft signatures in the binary
            microsoft_strings = [
                b'Microsoft Corporation',
                b'Windows NT',
                b'System32',
                b'KERNEL32.dll',
                b'ADVAPI32.dll'
            ]
            
            microsoft_indicators = sum(1 for sig in microsoft_strings if sig in header)
            
            # Known system binary file sizes (approximate ranges)
            file_size = len(header) if len(header) < 1024 else os.path.getsize(file_path)
            
            common_system_sizes = [
                (100000, 200000),    # Small utilities
                (300000, 600000),    # Medium utilities  
                (1000000, 2000000),  # Large system tools
            ]
            
            size_matches = any(min_size <= file_size <= max_size for min_size, max_size in common_system_sizes)
            
            # If it has Microsoft indicators and common size but unusual name
            if microsoft_indicators >= 2 and size_matches:
                # Check if filename is suspicious (not in common locations)
                suspicious_names = [
                    'update', 'install', 'setup', 'temp', 'new', 'copy',
                    'backup', 'old', 'test', '1', '2', 'final'
                ]
                
                filename_base = os.path.splitext(os.path.basename(file_path))[0].lower()
                if any(sus_name in filename_base for sus_name in suspicious_names):
                    return True
                    
        except Exception:
            pass
            
        return False
    
    def is_whitelisted_device(self, device):
        """Check if device is a whitelisted system device"""
        vid = device.get('vid', '').lower()
        pid = device.get('pid', '').lower()

        for (whitelist_vid, whitelist_pid), description in self.SYSTEM_DEVICE_WHITELIST.items():
            if whitelist_vid.lower() == vid:
                # If PID is None in whitelist, match all PIDs from this vendor
                if whitelist_pid is None or whitelist_pid.lower() == pid:
                    logger.debug(f"✓ Whitelisted device: {device.get('product', 'Unknown')} ({vid}:{pid}) - {description}")
                    return True
        return False

    def analyze_usb_device_with_retry(self, device):
        """
        Wrapper for USB analysis that handles mount detection with retry logic.

        This ensures storage devices are properly analyzed even if they're not
        mounted immediately when first detected.
        """
        import threading
        import time

        logger.info(f"🔍 [WRAPPER ENTRY] Entering retry wrapper for device: {device.get('product', 'Unknown')} (VID:{device.get('vid')}, PID:{device.get('pid')})")

        # Skip whitelisted system devices
        whitelist_result = self.is_whitelisted_device(device)
        logger.info(f"🔍 [WRAPPER WHITELIST] is_whitelisted_device() returned: {whitelist_result}")
        if whitelist_result:
            logger.info(f"⏭️  [WRAPPER SKIP] Device whitelisted, skipping analysis: {device.get('product', 'Unknown')}")
            return

        logger.info(f"📊 [WRAPPER STATE] Before mount search - storage={device.get('storage')}, mount_point={device.get('mount_point')}")

        # For storage devices, try to find mount point before analysis
        if device.get('storage'):
            logger.info(f"🔍 [WRAPPER MOUNT] Device is storage, searching for mount point...")
            mount_point = self.find_mount_point_for_device(device)
            logger.info(f"🔎 [WRAPPER MOUNT RESULT] Mount search returned: {mount_point}")
            if mount_point:
                device['mount_point'] = mount_point
                logger.info(f"✅ [WRAPPER MOUNT SET] Mount point found immediately and set: {mount_point}")
            else:
                logger.info(f"⏳ [WRAPPER MOUNT NONE] No mount point found yet for {device.get('product', 'Unknown')}")
        else:
            logger.info(f"📊 [WRAPPER NON-STORAGE] Device is not storage, skipping mount search")

        logger.info(f"📊 [WRAPPER STATE] After mount search - storage={device.get('storage')}, mount_point={device.get('mount_point')}")

        # Always run immediate analysis (will work for non-storage or already-mounted devices)
        logger.info(f"▶️  [WRAPPER ANALYZE] Calling analyze_usb_device() for immediate analysis...")
        self.analyze_usb_device(device)
        logger.info(f"✅ [WRAPPER ANALYZE] analyze_usb_device() completed")

        # For storage devices without mount points, schedule delayed retries
        logger.info(f"🔁 [WRAPPER RETRY CHECK] Checking retry condition: storage={device.get('storage')}, mount_point={device.get('mount_point')}")
        logger.info(f"🔁 [WRAPPER RETRY EVAL] storage={device.get('storage')} AND not mount_point={not device.get('mount_point')} = {device.get('storage') and not device.get('mount_point')}")

        if device.get('storage') and not device.get('mount_point'):
            logger.info(f"📅 [WRAPPER RETRY START] ✨ SCHEDULING RETRY! ✨ Creating retry thread for {device.get('product', 'Unknown')}")

            def delayed_analysis_with_retries():
                # Try 3 times with increasing delays: 2s, 5s, 8s
                retry_delays = [2, 5, 8]
                for attempt, delay in enumerate(retry_delays, 1):
                    time.sleep(delay)
                    logger.info(f"🔄 Retry attempt {attempt}/{len(retry_delays)} for {device.get('product', 'Unknown')} (waited {delay}s)")
                    mount_point = self.find_mount_point_for_device(device)
                    if mount_point:
                        device['mount_point'] = mount_point
                        logger.info(f"✅ Mount point found on retry {attempt}: {mount_point}")
                        self.analyze_usb_device(device)
                        return  # Success, exit retry loop
                    else:
                        logger.warning(f"⏳ Mount point not found on attempt {attempt}/{len(retry_delays)}")

                # All retries exhausted
                logger.error(f"❌ Mount point still not found after {len(retry_delays)} retry attempts for {device.get('product', 'Unknown')}")

            retry_thread = threading.Thread(target=delayed_analysis_with_retries, daemon=True)
            retry_thread.start()
            logger.info(f"📅 [WRAPPER RETRY THREAD] Retry thread started successfully")
        else:
            logger.info(f"⏭️  [WRAPPER NO RETRY] Retry NOT scheduled (condition not met)")

    def analyze_usb_device(self, device):
        """
        Comprehensive USB device analysis with detailed threat explanations.

        This is the main analysis function that combines all detection methods
        to assess whether a USB device is potentially malicious.
        """
        threats = []
        total_score = 0.0
        all_details = []
        
        # Check BadUSB signatures
        badusb_score = self.check_badusb_signatures(device)
        if badusb_score > 0.5:
            product = device.get('product', 'Unknown')
            vid = device.get('vid', '')
            pid = device.get('pid', '')
            
            # Find which BadUSB type was detected
            badusb_type = "Unknown BadUSB"
            for usb_type, info in self.badusb_signatures.items():
                if 'vid_pid' in info:
                    for known_vid, known_pid in info['vid_pid']:
                        if vid.lower() == known_vid and pid.lower() == known_pid:
                            badusb_type = usb_type.replace('_', ' ').title()
                            break
            
            details = f"{badusb_type} device detected ({vid}:{pid}) - Capable of automated keystroke injection, command execution, and data exfiltration"
            threats.append({
                'type': 'badusb_detected',
                'confidence': badusb_score,
                'details': details
            })
            all_details.append(details)
            total_score = max(total_score, badusb_score)
        
        # Check malicious behaviors with detailed explanations
        behavior_score, behavior_details = self.check_malicious_behaviors(device)
        
        # Lower threshold for storage devices to capture more information
        is_storage = device.get('storage', False) or device.get('vid', '').lower() == '0781'
        threshold = 0.1 if is_storage else 0.3
        
        logger.debug(f"🔍 Behavior analysis complete - Score: {behavior_score}, Threshold: {threshold}, Storage: {is_storage}")
        
        if behavior_score > threshold:
            threats.append({
                'type': 'malicious_usb_behavior',
                'confidence': behavior_score,
                'details': ' | '.join(behavior_details) if behavior_details else "Suspicious USB behavior detected"
            })
            all_details.extend(behavior_details)
            total_score = max(total_score, behavior_score)
        
        # Log threats with all details
        if threats:
            self.log_threat(device, threats, total_score, all_details)
        
        return threats, total_score
    
    def calculate_enhanced_threat_score(self, all_threats, device):
        """
        Calculate an enhanced threat score based on multiple factors and threat types.
        
        This function provides more sophisticated scoring that considers threat combinations,
        device characteristics, and the severity of different attack types.
        """
        base_score = 0.0
        threat_multipliers = []
        critical_threats = []
        
        # Categorize threats by type and severity
        threat_categories = {
            'known_malware': [],      # NEW: Highest priority for hash-matched malware
            'badusb_hardware': [],
            'malicious_files': [],
            'document_exploits': [],
            'lol_techniques': [],
            'masquerading': [],
            'behavioral': []
        }
        
        for threat in all_threats:
            threat_type = threat.get('type', '')
            confidence = threat.get('confidence', 0)
            
            # Prioritize known malware detection
            if threat_type == 'known_malware' or 'KNOWN MALWARE' in threat.get('details', ''):
                threat_categories['known_malware'].append(confidence)
                if confidence > 0.9:
                    critical_threats.append('Known Malware')
            elif threat_type == 'badusb_detected':
                threat_categories['badusb_hardware'].append(confidence)
                if confidence > 0.8:
                    critical_threats.append('Hardware BadUSB')
            elif 'file' in threat_type or 'document' in threat_type:
                if 'document' in threat_type:
                    threat_categories['document_exploits'].append(confidence)
                else:
                    threat_categories['malicious_files'].append(confidence)
            elif 'masquerading' in threat_type or 'double_extension' in threat_type:
                threat_categories['masquerading'].append(confidence)
            elif 'lol' in threat_type or 'living_off_land' in threat_type:
                threat_categories['lol_techniques'].append(confidence)
            else:
                threat_categories['behavioral'].append(confidence)
            
            base_score = max(base_score, confidence)
        
        # Apply threat combination multipliers
        active_categories = sum(1 for cat_threats in threat_categories.values() if cat_threats)
        
        if active_categories >= 4:
            # Multiple threat categories indicate sophisticated attack
            threat_multipliers.append(1.3)
        elif active_categories >= 3:
            threat_multipliers.append(1.2)
        elif active_categories >= 2:
            threat_multipliers.append(1.1)
        
        # Critical threat combinations (known malware gets highest priority)
        if threat_categories['known_malware']:
            # Known malware automatically gets maximum threat level
            threat_multipliers.append(1.5)  # Highest multiplier for confirmed malware
            critical_threats.append('Confirmed Malware Detection')
            
        if threat_categories['badusb_hardware'] and threat_categories['malicious_files']:
            threat_multipliers.append(1.25)  # Hardware + malicious files = very dangerous
            critical_threats.append('BadUSB with malicious payload')
        
        if threat_categories['known_malware'] and threat_categories['badusb_hardware']:
            threat_multipliers.append(1.4)  # Known malware + BadUSB = APT-level threat
            critical_threats.append('Known malware on BadUSB device')
        
        if threat_categories['document_exploits'] and threat_categories['lol_techniques']:
            threat_multipliers.append(1.2)  # Document exploits + LOL = targeted attack
            critical_threats.append('Document exploit with LOL techniques')
        
        if len(threat_categories['masquerading']) > 2:
            threat_multipliers.append(1.15)  # Multiple masquerading techniques
            critical_threats.append('Multiple masquerading techniques')
        
        # Device characteristic modifiers
        if device.get('hid') and device.get('storage'):
            threat_multipliers.append(1.1)  # Dual functionality is suspicious
        
        if not device.get('vendor') or device.get('vendor') == 'Unknown':
            threat_multipliers.append(1.05)  # Unknown vendors are more suspicious
        
        # Calculate final score
        final_score = base_score
        for multiplier in threat_multipliers:
            final_score *= multiplier
        
        # Cap at 1.0
        final_score = min(final_score, 1.0)
        
        return final_score, critical_threats, active_categories
    
    def generate_threat_summary(self, all_threats, device, enhanced_score, critical_threats):
        """Generate a comprehensive threat summary with actionable intelligence"""
        
        # Count threat types
        threat_counts = {}
        for threat in all_threats:
            threat_type = threat.get('type', 'unknown')
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        # Generate risk assessment
        if enhanced_score >= 0.9:
            risk_assessment = "CRITICAL - Immediate action required"
            recommendations = [
                "Isolate system immediately",
                "Scan for persistence mechanisms",
                "Check for lateral movement",
                "Perform full forensic analysis"
            ]
        elif enhanced_score >= 0.7:
            risk_assessment = "HIGH - Investigate immediately"
            recommendations = [
                "Disconnect device and quarantine",
                "Run full antivirus scan",
                "Check system logs for anomalies",
                "Monitor network traffic"
            ]
        elif enhanced_score >= 0.5:
            risk_assessment = "MEDIUM - Monitor closely"
            recommendations = [
                "Safe handling procedures",
                "Limited system exposure",
                "Regular monitoring",
                "User awareness training"
            ]
        else:
            risk_assessment = "LOW - Continue monitoring"
            recommendations = [
                "Standard security protocols",
                "Regular updates",
                "User education"
            ]
        
        # Create attack vector analysis with malware family info
        attack_vectors = []
        malware_families = []
        
        # Extract malware family information from threats
        for threat in all_threats:
            threat_details = threat.get('details', '')
            if 'KNOWN MALWARE' in threat_details:
                # Extract malware family from the threat details
                if ' - ' in threat_details:
                    parts = threat_details.split(' - ')
                    if len(parts) >= 2:
                        family_info = parts[1].split(' (')[0]  # Get family before parentheses
                        if family_info not in malware_families:
                            malware_families.append(family_info)
        
        if malware_families:
            attack_vectors.append(f"Known malware families: {', '.join(malware_families[:3])}")
        if any('badusb' in threat.get('type', '') for threat in all_threats):
            attack_vectors.append("Hardware-based keystroke injection")
        if any('file' in threat.get('type', '') for threat in all_threats):
            attack_vectors.append("Malicious file execution")
        if any('document' in threat.get('type', '') for threat in all_threats):
            attack_vectors.append("Document-based exploits")
        if any('masquer' in threat.get('type', '') for threat in all_threats):
            attack_vectors.append("Social engineering via file masquerading")
        
        return {
            'risk_assessment': risk_assessment,
            'attack_vectors': attack_vectors,
            'critical_threats': critical_threats,
            'recommendations': recommendations,
            'threat_counts': threat_counts,
            'malware_families': malware_families
        }
    
    def log_threat(self, device, threats, score, detailed_descriptions=None):
        """Log USB threat to Elasticsearch with enhanced scoring and detailed explanations"""
        if score < 0.3:
            return
        
        # Calculate enhanced threat score
        enhanced_score, critical_threats, active_categories = self.calculate_enhanced_threat_score(threats, device)
        
        # Generate comprehensive threat summary
        threat_summary = self.generate_threat_summary(threats, device, enhanced_score, critical_threats)
        
        threat_names = [t['type'] for t in threats]
        
        # Create detailed message with enhanced information
        if detailed_descriptions:
            primary_threats = detailed_descriptions[:2]
            detailed_message = " | ".join(primary_threats)
            if len(detailed_descriptions) > 2:
                detailed_message += f" | +{len(detailed_descriptions)-2} more threats"
        else:
            detailed_message = f"USB threat detected: {', '.join(threat_names)}"
        
        # Add critical threat summary to message
        if critical_threats:
            detailed_message = f"⚠️ {', '.join(critical_threats)} | {detailed_message}"
        
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'honeypot_id': 'honeyman-01',
            'source': 'usb_enhanced_detector',
            'log_type': 'usb_threat_detection',
            'detection_type': 'malicious_usb_device',
            'threat_score': round(score, 2),
            'enhanced_threat_score': round(enhanced_score, 2),
            'risk_level': 'critical' if enhanced_score > 0.8 else 'high' if enhanced_score > 0.6 else 'medium',
            'threats_detected': threat_names,
            'threat_categories_active': active_categories,
            'critical_threats': critical_threats,
            'attack_vectors': threat_summary['attack_vectors'],
            'risk_assessment': threat_summary['risk_assessment'],
            'recommendations': threat_summary['recommendations'],
            'device_info': {
                'vid': device.get('vid', ''),
                'pid': device.get('pid', ''),
                'vendor': device.get('vendor', ''),
                'product': device.get('product', ''),
                'serial': device.get('serial', ''),
                'class': device.get('class', ''),
                'hid': device.get('hid', False),
                'storage': device.get('storage', False)
            },
            'threat_details': threats,
            'threat_descriptions': detailed_descriptions,
            'threat_counts': threat_summary['threat_counts'],
            'malware_families_detected': threat_summary.get('malware_families', []),
            'message': detailed_message
        }
        
        try:
            self.es.index(index='honeypot-logs-new', document=log_entry)
            
            # Enhanced logging with more context
            logger.info(f"🚨 USB THREAT DETECTED: {threat_names}")
            logger.info(f"   📊 Score: {score:.2f} → Enhanced: {enhanced_score:.2f}")
            logger.info(f"   🎯 Risk Level: {threat_summary['risk_assessment']}")
            logger.info(f"   🔥 Active Threat Categories: {active_categories}")
            
            if critical_threats:
                logger.warning(f"   ⚠️ CRITICAL THREATS: {', '.join(critical_threats)}")
            
            if threat_summary['attack_vectors']:
                logger.info(f"   🎯 Attack Vectors: {', '.join(threat_summary['attack_vectors'])}")
            
            # Log malware family information prominently
            if threat_summary.get('malware_families'):
                logger.error(f"   🦠 MALWARE FAMILIES: {', '.join(threat_summary['malware_families'])}")
            
            # Log top recommendations
            if threat_summary['recommendations']:
                logger.info(f"   💡 Key Recommendation: {threat_summary['recommendations'][0]}")
            
            # Log detailed descriptions
            if detailed_descriptions:
                for i, desc in enumerate(detailed_descriptions[:3], 1):
                    if 'KNOWN MALWARE' in desc:
                        logger.error(f"   {i}. {desc}")  # Use error level for malware
                    else:
                        logger.info(f"   {i}. {desc}")
                    
        except Exception as e:
            logger.error(f"Failed to log threat: {e}")
    
    def run_continuous_monitoring(self):
        """Main monitoring loop"""
        logger.info("🚀 Starting ADVANCED Enhanced USB Detector")
        logger.info("🎯 Advanced Detection Capabilities:")
        logger.info("   🔌 BadUSB, Rubber Ducky, O.MG Cable, Flipper Zero detection")
        logger.info("   📁 Advanced autorun analysis (autorun.inf, desktop.ini, shell files)")
        logger.info("   🎭 File masquerading (double extensions, Unicode deception)")
        logger.info("   🎯 Attack pattern detection (PowerShell, social engineering)")
        logger.info("   📄 Document exploit detection (PDF, Office, RTF)")
        logger.info("   🛠️ Living-off-the-land technique detection")
        logger.info("   🧠 Enhanced threat scoring with multi-factor analysis")
        logger.info("   ⚡ Real-time behavioral analysis and entropy detection")
        
        # Start USB event monitoring
        observer = self.monitor_usb_events()
        
        # Initial scan of connected devices
        logger.info("📊 Scanning currently connected USB devices...")
        devices = self.get_usb_devices()
        for device in devices:
            self.analyze_usb_device_with_retry(device)
        
        try:
            while True:
                # Monitor HID keystrokes
                self.monitor_hid_keystrokes()
                
                # Periodic rescan
                time.sleep(30)
                
                # Check for new devices
                current_devices = self.get_usb_devices()
                for device in current_devices:
                    key = f"{device.get('vid', '')}:{device.get('pid', '')}:{device.get('serial', '')}"
                    if key not in self.known_devices:
                        logger.info(f"🔌 New USB device detected: {device.get('product', 'Unknown')}")
                        self.analyze_usb_device_with_retry(device)
                        self.known_devices[key] = device
                
        except KeyboardInterrupt:
            logger.info("🛑 Enhanced USB detector stopped")
            observer.stop()
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
            observer.stop()

if __name__ == "__main__":
    detector = EnhancedUSBDetector()
    detector.run_continuous_monitoring()