#!/usr/bin/env python3
"""
Multi-Vector Threat Detection System - Phase 3A
Combines USB, WiFi, and Network monitoring
"""
import threading
import time
import sys
import signal

# Import our detection modules
sys.path.append('.')
from usb_monitor import USBThreatMonitor
from usb_filesystem_monitor import USBFilesystemMonitor
from wifi_threat_detector import WiFiThreatDetector
from ble_enhanced_detector import EnhancedBLEThreatDetector

class MultiVectorDetection:
    def __init__(self):
        self.usb_device_monitor = USBThreatMonitor()
        self.usb_filesystem_monitor = USBFilesystemMonitor()
        self.wifi_monitor = WiFiThreatDetector()
        self.ble_monitor = EnhancedBLEThreatDetector()
        self.running = False
        
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n🛑 Received signal {signum}, shutting down multi-vector detection...")
        self.running = False
        
    def start_all_monitoring(self):
        """Start all threat detection components"""
        print("🎯 Starting Multi-Vector Threat Detection System")
        print("=" * 60)
        
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
            target=self.ble_monitor.monitor_enhanced_ble_threats,
            name='BLE-Threat-Monitor',
            daemon=True
        )
        ble_thread.start()
        threads.append(ble_thread)
        print("✅ BLE threat monitoring started")
        
        print(f"\n🎯 Multi-Vector Detection Active! ({len(threads)} components)")
        print("📋 Detection Capabilities:")
        print("   🔌 USB device threat detection")
        print("   📁 USB filesystem scanning")
        print("   📡 WiFi network threat detection")
        print("   🚨 Evil twin AP detection")
        print("   📱 BLE device fingerprinting")
        print("   🔥 Flipper Zero detection")
        print("   📊 Cross-vector threat correlation")
        print("")
        print("💡 System will detect threats across multiple attack vectors")
        print("🛑 Press Ctrl+C to stop all monitoring")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Multi-vector detection stopped")
            self.running = False

if __name__ == "__main__":
    system = MultiVectorDetection()
    system.start_all_monitoring()
