#!/usr/bin/env python3
"""
Test WiFi Detector V2
"""

import asyncio
import logging

# Setup test logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

async def test_wifi_detector():
    """Test WiFi detector with mock configuration"""

    # Import after setup
    from honeyman.rules import RuleEngine
    from honeyman.transport.protocol_handler import ProtocolHandler
    from honeyman.services.location_service import LocationService

    print("=" * 60)
    print("WIFI DETECTOR V2 TEST")
    print("=" * 60)

    # Create test config
    config_data = {
        'sensor_id': 'test_sensor',
        'sensor_name': 'Test Sensor',
        'rules_dir': 'rules',
        'wifi': {
            'scan_interval': 10,
            'whitelist_path': '/etc/honeyman/wifi_whitelist.json'
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
    print(f"   ✓ WiFi rules: {len(rule_engine.get_rules_by_category('wifi'))}")

    # List WiFi rules
    for rule in rule_engine.get_rules_by_category('wifi'):
        print(f"     - {rule.name} (severity: {rule.severity})")

    print("\n2. Initializing transport layer...")
    transport = ProtocolHandler(config_data['transport'])
    print("   ✓ Transport initialized (mock mode)")

    print("\n3. Initializing location service...")
    location_service = LocationService(config_data['location'])
    print("   ✓ Location service initialized")

    # Note: WiFi detector requires scapy and monitor mode for full functionality
    print("\n4. WiFi Detector Requirements:")
    print("   - Scapy library for packet capture")
    print("   - WiFi adapter with monitor mode support")
    print("   - Root/sudo privileges")
    print("   - airmon-ng for monitor mode management")

    # Test with simulated networks
    print("\n5. Simulating WiFi network detection...")

    test_networks = [
        {
            'name': 'WiFi Pineapple',
            'data': {
                'ssid': 'PineAP-Free',
                'bssid': '00:13:37:AA:BB:CC',
                'signal': '-45',
                'encryption': []
            }
        },
        {
            'name': 'ESP8266 Deauther',
            'data': {
                'ssid': 'pwned',
                'bssid': '5C:CF:7F:11:22:33',
                'signal': '-50',
                'encryption': []
            }
        },
        {
            'name': 'Flipper Zero WiFi',
            'data': {
                'ssid': 'FlipperZero',
                'bssid': 'AA:BB:CC:DD:EE:FF',
                'signal': '-40',
                'encryption': []
            }
        },
        {
            'name': 'Suspicious Free WiFi',
            'data': {
                'ssid': 'Free Public WiFi',
                'bssid': '11:22:33:44:55:66',
                'signal': '-55',
                'encryption': []
            }
        },
        {
            'name': 'Normal Home Network',
            'data': {
                'ssid': 'MyHomeNetwork',
                'bssid': 'AA:BB:CC:11:22:33',
                'signal': '-60',
                'encryption': ['WPA']
            }
        },
        {
            'name': 'Beacon Flood',
            'data': {
                'threat_type': 'beacon_flood',
                'unique_ssids_per_scan': 75
            }
        },
        {
            'name': 'Deauth Attack',
            'data': {
                'threat_type': 'deauth_attack',
                'bssid': 'AA:BB:CC:DD:EE:FF',
                'deauth_count_per_minute': 25
            }
        }
    ]

    for test in test_networks:
        print(f"\n   Testing: {test['name']}")
        matches = rule_engine.evaluate(test['data'], rule_set='wifi')

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
    print("\nNext steps for live testing:")
    print("1. Install scapy: pip install scapy")
    print("2. Install airmon-ng: apt-get install aircrack-ng")
    print("3. Run with sudo: sudo honeyman-agent -c config.yaml")
    print("4. Verify WiFi adapter supports monitor mode")
    print("5. Test with real WiFi attack tools")

if __name__ == '__main__':
    asyncio.run(test_wifi_detector())
