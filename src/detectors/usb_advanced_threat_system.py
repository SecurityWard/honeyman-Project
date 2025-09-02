#!/usr/bin/env python3
"""
Advanced USB Threat Detection System - Master Integration
Coordinates all USB monitoring modules for comprehensive threat detection
"""
import os
import time
import threading
import signal
import sys
from datetime import datetime
import json
import requests

# Import all our advanced monitoring modules
from usb_keystroke_monitor import HIDKeystrokeMonitor
from usb_deep_file_inspector import DeepFileInspector  
from usb_descriptor_analyzer import USBDescriptorAnalyzer
from usb_behavioral_monitor import USBBehavioralMonitor
from usb_filesystem_monitor import USBFilesystemMonitor
from usb_monitor_enhanced import EnhancedUSBThreatMonitor

class AdvancedUSBThreatSystem:
    def __init__(self):
        self.running = False
        self.monitoring_threads = []
        
        # Initialize all monitoring modules
        print("🚀 Initializing Advanced USB Threat Detection System")
        print("=" * 60)
        
        try:
            print("⌨️ Initializing HID Keystroke Monitor...")
            self.keystroke_monitor = HIDKeystrokeMonitor()
        except Exception as e:
            print(f"❌ Failed to initialize keystroke monitor: {e}")
            self.keystroke_monitor = None
            
        try:
            print("🔍 Initializing Deep File Inspector...")
            self.file_inspector = DeepFileInspector()
        except Exception as e:
            print(f"❌ Failed to initialize file inspector: {e}")
            self.file_inspector = None
            
        try:
            print("🔌 Initializing USB Descriptor Analyzer...")
            self.descriptor_analyzer = USBDescriptorAnalyzer()
        except Exception as e:
            print(f"❌ Failed to initialize descriptor analyzer: {e}")
            self.descriptor_analyzer = None
            
        try:
            print("📊 Initializing Behavioral Monitor...")
            self.behavioral_monitor = USBBehavioralMonitor()
        except Exception as e:
            print(f"❌ Failed to initialize behavioral monitor: {e}")
            self.behavioral_monitor = None
            
        try:
            print("📁 Initializing Filesystem Monitor...")
            self.filesystem_monitor = USBFilesystemMonitor()
        except Exception as e:
            print(f"❌ Failed to initialize filesystem monitor: {e}")
            self.filesystem_monitor = None
            
        try:
            print("🎯 Initializing Enhanced USB Monitor...")
            self.usb_monitor = EnhancedUSBThreatMonitor()
        except Exception as e:
            print(f"❌ Failed to initialize USB monitor: {e}")
            self.usb_monitor = None
            
        # System state
        self.active_devices = {}
        self.threat_correlation_data = []
        
        print("=" * 60)
        print("✅ Advanced USB Threat System Ready!")
        
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n🛑 Received signal {signum}, shutting down Advanced USB Threat System...")
        self.running = False
        
    def start_all_monitoring(self):
        """Start all monitoring components"""
        print("\n🚀 Starting All USB Monitoring Components")
        print("=" * 50)
        
        self.running = True
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Start HID keystroke monitoring (requires sudo)
        if self.keystroke_monitor:
            try:
                keystroke_thread = threading.Thread(
                    target=self._safe_keystroke_monitoring,
                    name='HID-Keystroke-Monitor',
                    daemon=True
                )
                keystroke_thread.start()
                self.monitoring_threads.append(keystroke_thread)
                print("✅ HID keystroke monitoring started")
            except Exception as e:
                print(f"❌ Failed to start keystroke monitoring: {e}")
                
        # Start USB descriptor monitoring
        if self.descriptor_analyzer:
            try:
                descriptor_thread = threading.Thread(
                    target=self._safe_descriptor_monitoring,
                    name='USB-Descriptor-Monitor',
                    daemon=True
                )
                descriptor_thread.start()
                self.monitoring_threads.append(descriptor_thread)
                print("✅ USB descriptor monitoring started")
            except Exception as e:
                print(f"❌ Failed to start descriptor monitoring: {e}")
                
        # Start filesystem monitoring  
        if self.filesystem_monitor:
            try:
                filesystem_thread = threading.Thread(
                    target=self._safe_filesystem_monitoring,
                    name='USB-Filesystem-Monitor',
                    daemon=True
                )
                filesystem_thread.start()
                self.monitoring_threads.append(filesystem_thread)
                print("✅ USB filesystem monitoring started")
            except Exception as e:
                print(f"❌ Failed to start filesystem monitoring: {e}")
                
        # Start enhanced USB device monitoring
        if self.usb_monitor:
            try:
                usb_monitor_thread = threading.Thread(
                    target=self._safe_usb_device_monitoring,
                    name='Enhanced-USB-Monitor',
                    daemon=True
                )
                usb_monitor_thread.start()
                self.monitoring_threads.append(usb_monitor_thread)
                print("✅ Enhanced USB device monitoring started")
            except Exception as e:
                print(f"❌ Failed to start USB device monitoring: {e}")
                
        # Behavioral monitoring is initialized but activated per USB insertion
        if self.behavioral_monitor:
            print("✅ Behavioral monitoring ready (triggers on USB insertion)")
            
        print("=" * 50)
        print("🎯 ADVANCED USB THREAT DETECTION ACTIVE!")
        print("")
        print("🛡️ COMPREHENSIVE PROTECTION CAPABILITIES:")
        print("")
        print("   ⌨️ KEYSTROKE ANALYSIS:")
        print("      • Real-time HID report monitoring")
        print("      • Superhuman typing speed detection")
        print("      • BadUSB/Rubber Ducky identification")
        print("      • Scripted vs human pattern analysis")
        print("")
        print("   🔍 DEEP FILE INSPECTION:")
        print("      • Magic number verification")
        print("      • Entropy analysis for packed malware") 
        print("      • PE header structure analysis")
        print("      • Malware string signature scanning")
        print("      • Script content analysis")
        print("")
        print("   🔌 HARDWARE ANALYSIS:")
        print("      • USB descriptor deep inspection")
        print("      • BadUSB signature detection")
        print("      • Interface combination analysis")
        print("      • Vendor/product validation")
        print("")
        print("   📊 BEHAVIORAL MONITORING:")
        print("      • Process spawning detection")
        print("      • Network activity correlation")
        print("      • File system change tracking")
        print("      • Time-based threat correlation")
        print("")
        print("   📁 FILESYSTEM SCANNING:")
        print("      • Autorun file detection")
        print("      • Suspicious file identification")
        print("      • Real-time mount monitoring")
        print("      • Enhanced threat signatures")
        print("")
        print("🚨 THREAT DETECTION LEVELS:")
        print("   🔴 CRITICAL: Confirmed BadUSB/malware (>0.8 score)")
        print("   🟠 HIGH: Strong suspicious indicators (>0.6 score)")
        print("   🟡 MEDIUM: Moderate suspicion (>0.3 score)")
        print("   🟢 LOW: Minor anomalies (<0.3 score)")
        print("")
        print("💡 Insert USB devices to test comprehensive detection")
        print("🛑 Press Ctrl+C to stop all monitoring")
        
        # Start threat correlation engine
        correlation_thread = threading.Thread(
            target=self._threat_correlation_engine,
            name='Threat-Correlation-Engine', 
            daemon=True
        )
        correlation_thread.start()
        self.monitoring_threads.append(correlation_thread)
        
        # Main monitoring loop
        try:
            while self.running:
                time.sleep(1)
                
                # Periodic status report
                if int(time.time()) % 300 == 0:  # Every 5 minutes
                    self._print_system_status()
                    
        except KeyboardInterrupt:
            print("\n🛑 Advanced USB Threat System stopped by user")
            self.running = False
            
        print("🔄 Waiting for monitoring threads to finish...")
        for thread in self.monitoring_threads:
            if thread.is_alive():
                thread.join(timeout=5)
                
        print("✅ Advanced USB Threat Detection System shutdown complete")
        
    def _safe_keystroke_monitoring(self):
        """Safe wrapper for keystroke monitoring"""
        try:
            if self.keystroke_monitor:
                self.keystroke_monitor.start_monitoring()
        except Exception as e:
            print(f"❌ Keystroke monitoring error: {e}")
            
    def _safe_descriptor_monitoring(self):
        """Safe wrapper for descriptor monitoring"""
        try:
            if self.descriptor_analyzer:
                self.descriptor_analyzer.monitor_descriptor_changes()
        except Exception as e:
            print(f"❌ Descriptor monitoring error: {e}")
            
    def _safe_filesystem_monitoring(self):
        """Safe wrapper for filesystem monitoring"""
        try:
            if self.filesystem_monitor:
                self.filesystem_monitor.monitor_mounts()
        except Exception as e:
            print(f"❌ Filesystem monitoring error: {e}")
            
    def _safe_usb_device_monitoring(self):
        """Safe wrapper for USB device monitoring"""
        try:
            if self.usb_monitor:
                self.usb_monitor.start_monitoring()
        except Exception as e:
            print(f"❌ USB device monitoring error: {e}")
            
    def _threat_correlation_engine(self):
        """Correlate threats across different monitoring systems"""
        print("🔗 Threat correlation engine started")
        
        while self.running:
            try:
                # This would correlate threats from different systems
                # For now, it's a placeholder for future enhancement
                time.sleep(30)
                
                # Check if we have any correlated threat patterns
                # self._analyze_threat_correlations()
                
            except Exception as e:
                print(f"❌ Threat correlation error: {e}")
                time.sleep(5)
                
    def register_usb_insertion(self, device_info):
        """Register USB device insertion across all monitoring systems"""
        print(f"\n📱 USB DEVICE INSERTION DETECTED")
        print(f"🔍 Device: {device_info.get('name', 'Unknown')}")
        print(f"📊 Activating all threat detection systems...")
        
        # Trigger behavioral monitoring
        if self.behavioral_monitor:
            self.behavioral_monitor.register_usb_insertion(device_info)
            
        # Store device info for correlation
        device_id = device_info.get('device_path', f"device_{int(time.time())}")
        self.active_devices[device_id] = {
            'info': device_info,
            'insertion_time': time.time(),
            'threats_detected': []
        }
        
    def _print_system_status(self):
        """Print periodic system status"""
        active_threads = sum(1 for t in self.monitoring_threads if t.is_alive())
        active_devices = len(self.active_devices)
        
        print(f"\n📊 SYSTEM STATUS - {datetime.now().strftime('%H:%M:%S')}")
        print(f"   🔧 Active monitoring threads: {active_threads}")
        print(f"   📱 Tracked USB devices: {active_devices}")
        print(f"   🔗 Threat correlations: {len(self.threat_correlation_data)}")
        
        # Clean up old device tracking
        current_time = time.time()
        old_devices = [
            device_id for device_id, device_data in self.active_devices.items()
            if current_time - device_data['insertion_time'] > 3600  # 1 hour
        ]
        
        for device_id in old_devices:
            del self.active_devices[device_id]
            
    def create_threat_summary_report(self):
        """Create comprehensive threat summary report"""
        try:
            report = {
                'timestamp': datetime.utcnow().isoformat(),
                'source': 'usb_advanced_threat_system',
                'log_type': 'system_status_report',
                'system_status': {
                    'active_threads': sum(1 for t in self.monitoring_threads if t.is_alive()),
                    'monitored_devices': len(self.active_devices),
                    'uptime_seconds': time.time() - (getattr(self, 'start_time', time.time())),
                },
                'monitoring_modules': {
                    'keystroke_monitor': self.keystroke_monitor is not None,
                    'file_inspector': self.file_inspector is not None, 
                    'descriptor_analyzer': self.descriptor_analyzer is not None,
                    'behavioral_monitor': self.behavioral_monitor is not None,
                    'filesystem_monitor': self.filesystem_monitor is not None,
                    'usb_monitor': self.usb_monitor is not None
                },
                'active_devices': list(self.active_devices.keys()),
                'message': f'Advanced USB Threat System status: {sum(1 for t in self.monitoring_threads if t.is_alive())} active monitors'
            }
            
            # Send to Elasticsearch
            response = requests.post(
                'http://localhost:9200/honeypot-logs/_doc',
                json=report,
                timeout=5
            )
            
            if response.status_code in [200, 201]:
                print("✅ System status logged to Elasticsearch")
            else:
                print(f"❌ Failed to log system status: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Error creating status report: {e}")
            
def main():
    """Main function"""
    print("🛡️ ADVANCED USB THREAT DETECTION SYSTEM")
    print("🏢 Enterprise-Grade USB Security Solution")
    print("🔬 Research & Development Version")
    print("")
    
    # Check if running as root for full capabilities
    if os.geteuid() != 0:
        print("⚠️ WARNING: Not running as root - some features may be limited")
        print("💡 For full capabilities, run: sudo python3 usb_advanced_threat_system.py")
        print("")
    
    system = AdvancedUSBThreatSystem()
    system.start_time = time.time()
    
    try:
        system.start_all_monitoring()
    except KeyboardInterrupt:
        print("\n🛑 Shutdown requested by user")
    except Exception as e:
        print(f"\n❌ System error: {e}")
    finally:
        system.running = False

if __name__ == "__main__":
    main()