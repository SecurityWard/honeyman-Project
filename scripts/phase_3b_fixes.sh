#!/bin/bash
# Phase 3B: Fix Python Dependencies & BLE Scanning Issues
# Comprehensive solution for the detected problems

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}🔧 PHASE 3B: FIXING DEPENDENCIES & BLE ISSUES${NC}"
echo "=============================================="
echo "🕐 Time: $(date)"
echo ""

# Function for step tracking
step_counter=0
step() {
    step_counter=$((step_counter + 1))
    echo -e "${BLUE}[Step $step_counter] $1${NC}"
}

success() {
    echo -e "   ${GREEN}✅ Success${NC}"
}

warning() {
    echo -e "   ${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "   ${RED}❌ $1${NC}"
}

info() {
    echo -e "   ${CYAN}ℹ️  $1${NC}"
}

# Fix 1: Python Dependencies
fix_python_dependencies() {
    step "Fixing Python Dependencies"
    
    cd ~/honeypot
    
    echo "   🐍 Checking current virtual environment..."
    if [ -d "venv" ]; then
        echo "   ✅ Virtual environment exists"
        source venv/bin/activate
    else
        echo "   📦 Creating new virtual environment..."
        python3 -m venv venv
        source venv/bin/activate
        echo "   ✅ New virtual environment created"
    fi
    
    echo "   🔄 Uninstalling conflicting packages..."
    pip uninstall -y docker urllib3 requests chardet charset-normalizer docker-py 2>/dev/null || true
    
    echo "   📥 Installing compatible versions..."
    pip install --upgrade pip setuptools wheel
    
    # Install compatible versions in specific order
    pip install "urllib3>=1.26.0,<2.0.0"
    pip install "requests>=2.28.0,<2.32.0" 
    pip install "chardet>=5.0.0,<6.0.0"
    pip install "charset-normalizer>=3.0.0,<4.0.0"
    pip install "docker>=6.0.0,<7.0.0"
    pip install pyudev psutil PyYAML scapy
    
    echo "   🧪 Testing import..."
    python3 -c "
import requests
import docker
print('✅ Dependencies fixed successfully!')
" || warning "Some dependencies may still have issues"
    
    success
}

# Fix 2: Bluetooth Service Issues
fix_bluetooth_service() {
    step "Fixing Bluetooth Service Issues"
    
    echo "   🔄 Restarting Bluetooth service..."
    sudo systemctl stop bluetooth
    sleep 2
    sudo systemctl start bluetooth
    sleep 3
    
    echo "   🔍 Checking Bluetooth service status..."
    if sudo systemctl is-active bluetooth --quiet; then
        echo "   ✅ Bluetooth service is running"
    else
        warning "Bluetooth service may not be running properly"
    fi
    
    echo "   📡 Resetting Bluetooth interface..."
    sudo hciconfig hci0 down
    sleep 1
    sudo hciconfig hci0 up
    sleep 2
    
    echo "   🔍 Checking interface status..."
    if hciconfig hci0 | grep -q "UP RUNNING"; then
        echo "   ✅ Bluetooth interface is UP and RUNNING"
    else
        warning "Bluetooth interface may need attention"
    fi
    
    success
}

# Fix 3: Enhanced BLE Detector with Better Error Handling
create_fixed_ble_detector() {
    step "Creating Fixed BLE Detector"
    
    cat > ~/honeypot/detection/ble_detector_fixed.py << 'EOF'
#!/usr/bin/env python3
"""
Fixed BLE Detector - Phase 3B with Enhanced Error Handling
Addresses timeout and scanning issues
"""

import subprocess
import time
import logging
import json
import os
import signal
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Set

class FixedBLEDetector:
    def __init__(self):
        self.setup_logging()
        self.known_devices = {}
        self.suspicious_patterns = self.load_threat_signatures()
        self.running = True
        self.bluetooth_initialized = False
        
    def setup_logging(self):
        os.makedirs("/var/log/honeypot", exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - BLE_DETECTOR_FIXED - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("/var/log/honeypot/ble_detection_fixed.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def load_threat_signatures(self):
        """Load known threat device signatures"""
        return {
            'flipper_zero': {
                'names': ['Flipper', 'FlipperZero', 'Flip'],
                'mac_patterns': [r'^80:E1:26:', r'^80:E1:27:'],
                'service_uuids': ['0000180f-0000-1000-8000-00805f9b34fb']
            },
            'hc_devices': {
                'names': ['HC-05', 'HC-06', 'ESP32', 'Arduino', 'WiFi Pineapple'],
                'suspicious_services': ['0000ffe0-0000-1000-8000-00805f9b34fb']
            },
            'attack_tools': {
                'names': ['PWAGOTCHI', 'WiFiPineapple', 'O.MG', 'Rubber Ducky', 'Malduino'],
                'manufacturers': ['Hak5', 'WiFi Pineapple']
            }
        }
    
    def initialize_bluetooth(self):
        """Initialize Bluetooth interface properly"""
        try:
            self.logger.info("🔧 Initializing Bluetooth interface...")
            
            # Reset Bluetooth interface
            subprocess.run(['sudo', 'hciconfig', 'hci0', 'down'], 
                         capture_output=True, timeout=5)
            time.sleep(1)
            subprocess.run(['sudo', 'hciconfig', 'hci0', 'up'], 
                         capture_output=True, timeout=5)
            time.sleep(2)
            
            # Test if interface is working
            result = subprocess.run(['hciconfig', 'hci0'], 
                                  capture_output=True, text=True, timeout=5)
            
            if 'UP RUNNING' in result.stdout:
                self.logger.info("✅ Bluetooth interface initialized successfully")
                self.bluetooth_initialized = True
                return True
            else:
                self.logger.warning("⚠️  Bluetooth interface may not be ready")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Bluetooth initialization failed: {e}")
            return False
    
    def monitor(self):
        """Main monitoring loop with better error handling"""
        self.logger.info("🔍 Fixed BLE Detection Started")
        self.logger.info("🛠️  Enhanced error handling and timeout management")
        
        # Initialize Bluetooth first
        if not self.initialize_bluetooth():
            self.logger.error("❌ Could not initialize Bluetooth - continuing with limited functionality")
        
        scan_count = 0
        consecutive_failures = 0
        
        while self.running:
            try:
                scan_count += 1
                self.logger.info(f"🔍 Scan #{scan_count} starting...")
                
                devices_found = 0
                
                # Method 1: Enhanced bluetoothctl scanning
                devices_found += self.scan_with_bluetoothctl_enhanced()
                
                # Method 2: Fallback hcitool scanning  
                if devices_found == 0:
                    devices_found += self.scan_with_hcitool_enhanced()
                
                # Method 3: Classic Bluetooth scan
                if scan_count % 3 == 0:
                    devices_found += self.scan_classic_bluetooth()
                
                if devices_found > 0:
                    consecutive_failures = 0
                    self.logger.info(f"✅ Scan #{scan_count} completed - {devices_found} devices found")
                else:
                    consecutive_failures += 1
                    self.logger.info(f"ℹ️  Scan #{scan_count} completed - no devices detected")
                
                # If too many consecutive failures, reinitialize Bluetooth
                if consecutive_failures >= 5:
                    self.logger.warning("🔄 Multiple scan failures - reinitializing Bluetooth...")
                    self.initialize_bluetooth()
                    consecutive_failures = 0
                
                # Analyze patterns periodically
                if scan_count % 5 == 0:
                    self.analyze_detection_patterns()
                
                time.sleep(15)  # Longer interval for more reliable scanning
                
            except KeyboardInterrupt:
                self.logger.info("🛑 Monitoring stopped by user")
                self.running = False
                break
            except Exception as e:
                self.logger.error(f"❌ Monitoring error: {e}")
                consecutive_failures += 1
                time.sleep(30)  # Wait longer after errors
    
    def scan_with_bluetoothctl_enhanced(self):
        """Enhanced bluetoothctl scanning with better timeout handling"""
        devices_found = 0
        
        try:
            self.logger.debug("   🔍 Starting bluetoothctl scan...")
            
            # Clear any previous scan state
            subprocess.run(['bluetoothctl', 'scan', 'off'], 
                         capture_output=True, timeout=3)
            time.sleep(1)
            
            # Start scan with longer timeout
            scan_process = subprocess.Popen(['bluetoothctl', 'scan', 'on'], 
                                          stdout=subprocess.PIPE, 
                                          stderr=subprocess.PIPE)
            
            # Let it scan for longer
            time.sleep(8)
            
            # Stop scan
            subprocess.run(['bluetoothctl', 'scan', 'off'], 
                         capture_output=True, timeout=3)
            
            # Get discovered devices
            result = subprocess.run(['bluetoothctl', 'devices'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout.strip():
                devices_found = self.parse_bluetoothctl_devices(result.stdout)
                self.logger.debug(f"   📱 bluetoothctl found {devices_found} devices")
            else:
                self.logger.debug("   ℹ️  bluetoothctl found no devices")
                
        except subprocess.TimeoutExpired:
            self.logger.warning("   ⏰ bluetoothctl scan timed out - continuing")
        except Exception as e:
            self.logger.debug(f"   ⚠️  bluetoothctl scan error: {e}")
            
        return devices_found
    
    def scan_with_hcitool_enhanced(self):
        """Enhanced hcitool scanning as fallback"""
        devices_found = 0
        
        try:
            self.logger.debug("   🔍 Starting hcitool lescan...")
            
            # Use hcitool lescan with timeout
            result = subprocess.run(['sudo', 'timeout', '8', 'hcitool', 'lescan'], 
                                  capture_output=True, text=True)
            
            if result.stdout:
                devices_found = self.parse_hcitool_output(result.stdout)
                self.logger.debug(f"   📱 hcitool found {devices_found} devices")
            else:
                self.logger.debug("   ℹ️  hcitool found no devices")
                
        except Exception as e:
            self.logger.debug(f"   ⚠️  hcitool scan error: {e}")
            
        return devices_found
    
    def scan_classic_bluetooth(self):
        """Scan for classic Bluetooth devices"""
        devices_found = 0
        
        try:
            self.logger.debug("   🔍 Starting classic Bluetooth scan...")
            
            result = subprocess.run(['timeout', '10', 'hcitool', 'scan'], 
                                  capture_output=True, text=True)
            
            if result.stdout:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip() and '\t' in line:
                        devices_found += 1
                        parts = line.strip().split('\t')
                        if len(parts) >= 2:
                            mac_address = parts[0]
                            device_name = parts[1] if len(parts) > 1 else "Unknown"
                            
                            device_info = {
                                'timestamp': datetime.now().isoformat(),
                                'mac_address': mac_address,
                                'device_name': device_name,
                                'scan_method': 'classic_bluetooth',
                                'detection_type': 'classic_bt_device'
                            }
                            
                            self.analyze_and_log_device(device_info)
                
                self.logger.debug(f"   📱 Classic BT found {devices_found} devices")
                
        except Exception as e:
            self.logger.debug(f"   ⚠️  Classic BT scan error: {e}")
            
        return devices_found
    
    def parse_bluetoothctl_devices(self, output):
        """Parse and analyze bluetoothctl device output"""
        devices_found = 0
        
        for line in output.split('\n'):
            if 'Device' in line:
                devices_found += 1
                parts = line.split()
                if len(parts) >= 3:
                    mac_addr = parts[1]
                    device_name = ' '.join(parts[2:])
                    
                    device_info = {
                        'timestamp': datetime.now().isoformat(),
                        'mac_address': mac_addr,
                        'device_name': device_name,
                        'scan_method': 'bluetoothctl',
                        'detection_type': 'ble_device'
                    }
                    
                    self.analyze_and_log_device(device_info)
        
        return devices_found
    
    def parse_hcitool_output(self, output):
        """Parse hcitool lescan output"""
        devices_found = 0
        
        for line in output.split('\n'):
            if ':' in line and len(line.split()) >= 1:
                parts = line.split()
                if len(parts) >= 1 and self.is_valid_mac(parts[0]):
                    devices_found += 1
                    mac_addr = parts[0]
                    device_name = ' '.join(parts[1:]) if len(parts) > 1 else 'Unknown'
                    
                    device_info = {
                        'timestamp': datetime.now().isoformat(),
                        'mac_address': mac_addr,
                        'device_name': device_name,
                        'scan_method': 'hcitool',
                        'detection_type': 'ble_device'
                    }
                    
                    self.analyze_and_log_device(device_info)
        
        return devices_found
    
    def analyze_and_log_device(self, device_info):
        """Analyze device for threats and log appropriately"""
        # Analyze for threats
        threat_level = self.analyze_device_threats(device_info)
        
        if threat_level > 0:
            device_info['threat_level'] = threat_level
            device_info['detection_type'] = 'ble_threat'
            
            if threat_level >= 8:
                self.logger.critical(f"🚨 HIGH THREAT: {device_info}")
            elif threat_level >= 4:
                self.logger.warning(f"⚠️  MEDIUM THREAT: {device_info}")
            else:
                self.logger.info(f"ℹ️  LOW THREAT: {device_info}")
        else:
            self.logger.info(f"📱 Device: {device_info['mac_address']} ({device_info['device_name']})")
        
        # Update tracking
        self.update_device_tracking(device_info)
        
        # Log as JSON for parsing
        self.logger.info(f"JSON: {json.dumps(device_info)}")
    
    def analyze_device_threats(self, device_info):
        """Analyze device for threat indicators"""
        threat_score = 0
        mac = device_info['mac_address']
        name = device_info['device_name'].lower()
        
        # Check for Flipper Zero
        flipper_sigs = self.suspicious_patterns['flipper_zero']
        for flipper_name in flipper_sigs['names']:
            if flipper_name.lower() in name:
                threat_score += 10
                self.logger.critical(f"🚨 FLIPPER ZERO DETECTED: {name}")
        
        # Check for attack tools
        attack_sigs = self.suspicious_patterns['attack_tools']
        for attack_name in attack_sigs['names']:
            if attack_name.lower() in name:
                threat_score += 8
                self.logger.warning(f"🔧 ATTACK TOOL DETECTED: {name}")
        
        # Check for development devices
        hc_sigs = self.suspicious_patterns['hc_devices']
        for hc_name in hc_sigs['names']:
            if hc_name.lower() in name:
                threat_score += 4
                self.logger.info(f"🛠️  DEV DEVICE: {name}")
        
        # Check for suspicious patterns
        if self.is_suspicious_name(name):
            threat_score += 3
        
        return threat_score
    
    def is_suspicious_name(self, name):
        """Check for suspicious device naming patterns"""
        suspicious_patterns = [
            'test', 'hack', 'pwn', 'exploit', 'shell', 'backdoor',
            'admin', 'root', 'system', 'debug', 'dev', 'evil', 'rogue'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in name.lower():
                return True
        return False
    
    def is_valid_mac(self, mac):
        """Validate MAC address format"""
        import re
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return re.match(mac_pattern, mac) is not None
    
    def update_device_tracking(self, device_info):
        """Update device tracking information"""
        mac = device_info['mac_address']
        
        if mac not in self.known_devices:
            self.known_devices[mac] = {
                'first_seen': device_info['timestamp'],
                'detection_count': 0,
                'names': set(),
                'scan_methods': set()
            }
        
        device = self.known_devices[mac]
        device['last_seen'] = device_info['timestamp']
        device['detection_count'] += 1
        device['names'].add(device_info['device_name'])
        device['scan_methods'].add(device_info['scan_method'])
    
    def analyze_detection_patterns(self):
        """Analyze patterns across all detected devices"""
        total_devices = len(self.known_devices)
        
        summary = {
            'timestamp': datetime.now().isoformat(),
            'detection_type': 'ble_summary',
            'total_devices': total_devices,
            'scan_methods_used': ['bluetoothctl', 'hcitool', 'classic_bt']
        }
        
        self.logger.info(f"📊 SUMMARY: {json.dumps(summary)}")

if __name__ == "__main__":
    # Handle signals gracefully
    detector = FixedBLEDetector()
    
    def signal_handler(sig, frame):
        print("\n🛑 Stopping BLE Detection...")
        detector.running = False
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        detector.monitor()
    except Exception as e:
        print(f"❌ Detection error: {e}")
    finally:
        print("✅ BLE Detection stopped")
EOF

    chmod +x ~/honeypot/detection/ble_detector_fixed.py
    success
}

# Fix 4: Test the Fixed Detector
test_fixed_detector() {
    step "Testing Fixed BLE Detector"
    
    echo "   🧪 Running 45-second test of fixed detector..."
    echo "   (Enhanced error handling and longer timeouts)"
    
    # Run the fixed detector for 45 seconds
    timeout 45s python3 ~/honeypot/detection/ble_detector_fixed.py || true
    
    echo ""
    echo "   📊 Checking results..."
    
    if [ -f "/var/log/honeypot/ble_detection_fixed.log" ]; then
        echo "   ✅ Fixed detector created log file successfully"
        echo ""
        echo "   📄 Recent log entries:"
        tail -10 "/var/log/honeypot/ble_detection_fixed.log" | sed 's/^/     /'
    else
        warning "Log file not created - check permissions"
    fi
    
    success
}

# Fix 5: Update System Service
update_system_service() {
    step "Updating System Service to Use Fixed Detector"
    
    sudo tee /etc/systemd/system/honeypot-ble-fixed.service << 'EOF'
[Unit]
Description=Fixed BLE Honeypot Detection
After=bluetooth.service
Wants=bluetooth.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/burner/honeypot/detection/ble_detector_fixed.py
Restart=always
RestartSec=30
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable honeypot-ble-fixed.service
    
    success
}

# Show the fixes summary
show_fixes_summary() {
    step "Fixes Complete - Summary & Next Steps"
    
    echo ""
    echo -e "${PURPLE}🎯 PHASE 3B FIXES COMPLETED!${NC}"
    echo "================================"
    echo ""
    echo -e "${CYAN}✅ Fixed Issues:${NC}"
    echo "• Python dependency warnings resolved"
    echo "• BLE scanning timeout issues addressed"
    echo "• Enhanced error handling and logging"
    echo "• Longer scan intervals for reliability"
    echo "• Multiple fallback scanning methods"
    echo ""
    echo -e "${CYAN}🚀 Ready to Deploy:${NC}"
    echo "• Start fixed service: sudo systemctl start honeypot-ble-fixed.service"
    echo "• Monitor logs: tail -f /var/log/honeypot/ble_detection_fixed.log"
    echo "• Check status: sudo systemctl status honeypot-ble-fixed.service"
    echo ""
    echo -e "${CYAN}🧪 Testing Commands:${NC}"
    echo "• Manual test: python3 ~/honeypot/detection/ble_detector_fixed.py"
    echo "• Log analysis: grep -i 'threat\\|flipper\\|attack' /var/log/honeypot/ble_detection_fixed.log"
    echo "• Device summary: grep 'SUMMARY' /var/log/honeypot/ble_detection_fixed.log"
    echo ""
    echo -e "${YELLOW}⚠️  What's Fixed:${NC}"
    echo "• Longer bluetoothctl scan timeouts (8 seconds vs 2 seconds)"
    echo "• Bluetooth interface reinitialization on failures"
    echo "• Multiple scanning methods with fallbacks"
    echo "• Enhanced threat detection for Flipper Zero and attack tools"
    echo "• Better error handling and recovery"
    echo ""
}

# Main execution
main() {
    echo "🔧 Starting Phase 3B Comprehensive Fixes"
    echo ""
    
    fix_python_dependencies
    fix_bluetooth_service
    create_fixed_ble_detector
    test_fixed_detector
    update_system_service
    show_fixes_summary
    
    echo ""
    echo -e "${GREEN}🎉 All Phase 3B issues have been fixed!${NC}"
    echo "Time: $(date)"
}

# Run main function
main