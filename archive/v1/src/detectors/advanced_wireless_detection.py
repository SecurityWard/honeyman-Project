#!/usr/bin/env python3
"""
Advanced Wireless Detection System - Phase 3B Complete
Combines WiFi, BLE, and AirDrop monitoring
"""
import threading
import time
import sys
import signal

# Import all detection modules
sys.path.append('.')
from usb_enhanced_detector import EnhancedUSBDetector
from wifi_enhanced_detector import EnhancedWiFiDetector  
from ble_enhanced_detector import EnhancedBLEThreatDetector
from airdrop_threat_detector import AirDropThreatDetector

class AdvancedWirelessDetection:
    def __init__(self):
        self.usb_monitor = EnhancedUSBDetector()
        self.wifi_monitor = EnhancedWiFiDetector()
        self.ble_monitor = EnhancedBLEThreatDetector()
        self.airdrop_monitor = AirDropThreatDetector()
        self.running = False
        
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n🛑 Received signal {signum}, shutting down advanced wireless detection...")
        self.running = False
        
    def start_all_monitoring(self):
        """Start all threat detection components"""
        print("🌐 Starting Enhanced Advanced Wireless Detection System")
        print("=" * 65)
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        self.running = True
        threads = []
        
        # Start enhanced USB monitoring
        usb_thread = threading.Thread(
            target=self.usb_monitor.run_continuous_monitoring,
            name='Enhanced-USB-Monitor',
            daemon=True
        )
        usb_thread.start()
        threads.append(usb_thread)
        print("✅ Enhanced USB threat monitoring started")
        
        # Start enhanced WiFi monitoring
        wifi_thread = threading.Thread(
            target=self.wifi_monitor.monitor_wifi_threats,
            name='Enhanced-WiFi-Monitor',
            daemon=True
        )
        wifi_thread.start()
        threads.append(wifi_thread)
        print("✅ Enhanced WiFi threat monitoring started")
        
        # Start enhanced BLE monitoring
        ble_thread = threading.Thread(
            target=self.ble_monitor.monitor_enhanced_ble_threats,
            name='Enhanced-BLE-Monitor',
            daemon=True
        )
        ble_thread.start()
        threads.append(ble_thread)
        print("✅ Enhanced BLE threat monitoring started")
        
        # Start AirDrop monitoring
        airdrop_thread = threading.Thread(
            target=self.airdrop_monitor.monitor_airdrop_threats,
            name='AirDrop-Threat-Monitor',
            daemon=True
        )
        airdrop_thread.start()
        threads.append(airdrop_thread)
        print("✅ AirDrop threat monitoring started")
        
        print(f"\n🌐 Enhanced Wireless Detection Active! ({len(threads)} components)")
        print("📋 Enhanced Detection Capabilities:")
        print("   🔌 Enhanced USB threats (BadUSB, Rubber Ducky, malicious devices)")
        print("   📡 Enhanced WiFi attacks (Evil twin with reduced false positives, hacking tools)")
        print("   📱 Enhanced BLE threats (Flipper Zero, custom firmware, Apple spoofing)")
        print("   📤 AirDrop abuse and proximity attacks")
        print("   🔗 Cross-vector attack correlation")
        print("   🧠 Advanced behavioral analysis and threat scoring")
        print("")
        print("💡 Comprehensive wireless attack surface monitoring with intelligent filtering")
        print("🛑 Press Ctrl+C to stop all monitoring")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Enhanced wireless detection stopped")
            self.running = False

if __name__ == "__main__":
    system = AdvancedWirelessDetection()
    system.start_all_monitoring()
