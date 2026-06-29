#!/usr/bin/env python3
"""
Test USB Detector V2
"""

import asyncio
import logging
from pathlib import Path

# Setup test logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

async def test_usb_detector():
    """Test USB detector with mock configuration"""

    # Import after setup
    from honeyman.rules import RuleEngine
    from honeyman.core import ConfigManager
    from honeyman.transport.protocol_handler import ProtocolHandler
    from honeyman.services.location_service import LocationService
    from honeyman.detectors.usb_detector import UsbDetector

    print("=" * 60)
    print("USB DETECTOR V2 TEST")
    print("=" * 60)

    # Create test config
    config_data = {
        'sensor_id': 'test_sensor',
        'sensor_name': 'Test Sensor',
        'rules_dir': 'rules',
        'usb': {
            'hash_database_path': '/var/lib/honeyman/malware_hashes.db'
        },
        'transport': {
            'protocol': 'http',
            'http': {
                'base_url': 'http://localhost:3000',
                'api_key': 'test_key'
            }
        },
        'location': {
            'enabled': False
        }
    }

    # Mock config
    class MockConfig:
        def __init__(self, data):
            self.config = data

        def get(self, key, default=None):
            keys = key.split('.')
            value = self.config
            for k in keys:
                if isinstance(value, dict):
                    value = value.get(k)
                else:
                    return default
                if value is None:
                    return default
            return value

    config = MockConfig(config_data)

    # Initialize components
    print("\n1. Loading detection rules...")
    rule_engine = RuleEngine('rules')
    print(f"   ✓ Loaded {len(rule_engine.rules)} rules")
    print(f"   ✓ USB rules: {len(rule_engine.get_rules_by_category('usb'))}")

    # List USB rules
    for rule in rule_engine.get_rules_by_category('usb'):
        print(f"     - {rule.name} (severity: {rule.severity})")

    print("\n2. Initializing transport layer...")
    transport = ProtocolHandler(config_data['transport'])
    print("   ✓ Transport initialized (mock mode)")

    print("\n3. Initializing location service...")
    location_service = LocationService(config_data['location'])
    print("   ✓ Location service initialized")

    print("\n4. Initializing USB detector...")
    detector = UsbDetector(
        rule_engine=rule_engine,
        transport=transport,
        config=config,
        location_service=location_service
    )
    print("   ✓ USB detector initialized")

    # Test with simulated device
    print("\n5. Simulating USB device insertion...")

    test_devices = [
        {
            'name': 'Rubber Ducky',
            'data': {
                'vid': '03eb',
                'pid': '2401',
                'vid_pid': '03eb:2401',
                'manufacturer': 'ATMEL',
                'product_name': 'USB Device',
                'device_class': 'hid'
            }
        },
        {
            'name': 'Bash Bunny',
            'data': {
                'vid': 'f000',
                'pid': 'ff00',
                'vid_pid': 'f000:ff00',
                'manufacturer': 'Hak5',
                'product_name': 'Bash Bunny',
                'device_class': 'storage'
            }
        },
        {
            'name': 'Normal USB Drive',
            'data': {
                'vid': '0781',
                'pid': '5567',
                'vid_pid': '0781:5567',
                'manufacturer': 'SanDisk',
                'product_name': 'Cruzer Blade',
                'device_class': 'storage'
            }
        }
    ]

    for test in test_devices:
        print(f"\n   Testing: {test['name']}")
        matches = rule_engine.evaluate(test['data'], rule_set='usb')

        if matches:
            print(f"   ⚠️  THREAT DETECTED!")
            for rule in matches:
                print(f"       - Rule: {rule.name}")
                print(f"       - Severity: {rule.severity}")
                print(f"       - Threat Type: {rule.threat_type}")
        else:
            print(f"   ✓  No threats detected")

    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Connect real USB devices for live testing")
    print("2. Verify pyudev detection")
    print("3. Test with malware hash database")
    print("4. Validate MQTT transport")

if __name__ == '__main__':
    asyncio.run(test_usb_detector())
