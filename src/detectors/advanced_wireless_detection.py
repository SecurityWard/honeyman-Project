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
from usb_monitor import USBThreatMonitor
from usb_filesystem_monitor import USBFilesystemMonitor
from wifi_threat_detector import WiFiThreatDetector
from ble_threat_detector import BLEThreatDetector
from airdrop_threat_detector import AirDropThreatDetector

class AdvancedWirelessDetection:
    def __init__(self):
        self.usb_device_monitor = USBThreatMonitor()
        self.usb_filesystem_monitor = USBFilesystemMonitor()
        self.wifi_monitor = WiFiThreatDetector()
        self.ble_monitor = BLEThreatDetector()
        self.airdrop_monitor = AirDropThreatDetector()
        self.running = False
        
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n🛑 Received signal {signum}, shutting down advanced wireless detection...")
        self.running = False
        
    def start_all_monitoring(self):
        """Start all threat detection components"""
        print("🌐 Starting Advanced Wireless Detection System - Phase 3B")
        print("=" * 65)
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        self.running = True
        threads = []
        
        # Start USB device monitoring
        usb_device_thread = threading.Thread(
            target=self.usb_device_monitor.start_monitoring,
            name='USB-Device-Monitor',
            daemon=True
        )
        usb_device_thread.start()
        threads.append(usb_device_thread)
        print("✅ USB device monitoring started")
        
        # Start USB filesystem monitoring
        usb_fs_thread = threading.Thread(
            target=self.usb_filesystem_monitor.monitor_mounts,
            name='USB-Filesystem-Monitor',
            daemon=True
        )
        usb_fs_thread.start()
        threads.append(usb_fs_thread)
        print("✅ USB filesystem monitoring started")
        
        # Start WiFi monitoring
        wifi_thread = threading.Thread(
            target=self.wifi_monitor.monitor_wifi_threats,
            name='WiFi-Threat-Monitor',
            daemon=True
        )
        wifi_thread.start()
        threads.append(wifi_thread)
        print("✅ WiFi threat monitoring started")
        
        # Start BLE monitoring
        ble_thread = threading.Thread(
            target=self.ble_monitor.monitor_ble_threats,
            name='BLE-Threat-Monitor',
            daemon=True
        )
        ble_thread.start()
        threads.append(ble_thread)
        print("✅ BLE threat monitoring started")
        
        # Start AirDrop monitoring
        airdrop_thread = threading.Thread(
            target=self.airdrop_monitor.monitor_airdrop_threats,
            name='AirDrop-Threat-Monitor',
            daemon=True
        )
        airdrop_thread.start()
        threads.append(airdrop_thread)
        print("✅ AirDrop threat monitoring started")
        
        print(f"\n🌐 Advanced Wireless Detection Active! ({len(threads)} components)")
        print("📋 Detection Capabilities:")
        print("   🔌 USB device and filesystem threats")
        print("   📡 WiFi network attacks (Evil twin, beacon flooding)")
        print("   📱 BLE threats (Flipper Zero, ESP32 attacks)")
        print("   📤 AirDrop abuse and proximity attacks")
        print("   🔗 Cross-vector attack correlation")
        print("")
        print("💡 Comprehensive wireless attack surface monitoring")
        print("🛑 Press Ctrl+C to stop all monitoring")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Advanced wireless detection stopped")
            self.running = False

if __name__ == "__main__":
    system = AdvancedWirelessDetection()
    system.start_all_monitoring()
