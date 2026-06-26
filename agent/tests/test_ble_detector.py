#!/usr/bin/env python3
"""
Test script for BLE Detector

Tests BLE threat detection against YAML rules
"""

import asyncio
import sys
import logging
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from honeyman.detectors.ble_detector import BleDetector
from honeyman.rules.rule_engine import RuleEngine
from honeyman.rules.rule_loader import RuleLoader
from honeyman.transport.protocol_handler import ProtocolHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MockTransport:
    """Mock transport for testing"""

    def __init__(self):
        self.threats = []

    async def send(self, data, topic='threats'):
        """Store threat instead of sending"""
        self.threats.append(data)
        logger.info(f"[THREAT DETECTED] {data['threat_type']}")
        logger.info(f"  Device: {data.get('device_name', 'Unknown')} ({data.get('mac_address', 'Unknown')})")
        logger.info(f"  Severity: {data['severity']}")
        logger.info(f"  Matched Rules: {[r['name'] for r in data.get('matched_rules', [])]}")
        return True


async def test_ble_detector():
    """Test BLE detector"""

    logger.info("=" * 80)
    logger.info("BLE Detector Test")
    logger.info("=" * 80)

    # Configuration
    config = {
        'sensor_id': 'test-sensor-001',
        'ble': {
            'scan_interval': 10.0,
            'scan_duration': 5.0,
            'use_bleak': True,  # Will fall back to bluetoothctl if bleak unavailable
            'track_services': True,
            'rssi_threshold': -90,
            'whitelist_macs': [],
            'whitelist_names': ['MyPhone', 'MyWatch']
        },
        'location': {
            'latitude': 37.7749,
            'longitude': -122.4194,
            'method': 'static'
        }
    }

    # Initialize components
    logger.info("\nInitializing components...")

    rules_dir = Path(__file__).parent / 'rules' / 'ble'
    rule_loader = RuleLoader(str(rules_dir))
    rule_engine = RuleEngine(rule_loader)

    transport = MockTransport()

    detector = BleDetector(config, rule_engine, transport)

    # Initialize detector
    try:
        await detector.initialize()
    except Exception as e:
        logger.error(f"Failed to initialize BLE detector: {e}")
        logger.info("\nNote: BLE scanning requires:")
        logger.info("  - bleak library (pip install bleak) OR")
        logger.info("  - bluetoothctl command available")
        logger.info("  - Bluetooth adapter enabled")
        return

    logger.info(f"\nBLE detector initialized successfully")
    logger.info(f"Detection method: {'bleak' if detector.use_bleak else 'bluetoothctl'}")
    logger.info(f"Scan interval: {detector.scan_interval}s")
    logger.info(f"RSSI threshold: {detector.rssi_threshold} dBm")

    # Load rules
    rule_count = len(rule_loader.rules)
    logger.info(f"\nLoaded {rule_count} BLE rules:")
    for rule_id, rule in rule_loader.rules.items():
        logger.info(f"  - {rule.name} (severity: {rule.severity})")

    logger.info("\n" + "=" * 80)
    logger.info("Starting BLE scan...")
    logger.info("This will scan for BLE devices and evaluate them against threat rules")
    logger.info("Scanning for 30 seconds. Press Ctrl+C to stop early.")
    logger.info("=" * 80 + "\n")

    # Run detector for 30 seconds
    try:
        detector_task = asyncio.create_task(detector.start())

        await asyncio.sleep(30)

        await detector.shutdown()
        detector_task.cancel()

        try:
            await detector_task
        except asyncio.CancelledError:
            pass

    except KeyboardInterrupt:
        logger.info("\nStopping detector...")
        await detector.shutdown()

    # Display results
    logger.info("\n" + "=" * 80)
    logger.info("Scan Results")
    logger.info("=" * 80)

    logger.info(f"\nDevices discovered: {len(detector.device_history)}")

    if detector.device_history:
        logger.info("\nDiscovered Devices:")
        for mac, device in detector.device_history.items():
            logger.info(f"\n  MAC: {mac}")
            logger.info(f"    Name: {device.get('device_name', 'Unknown')}")
            logger.info(f"    RSSI: {device.get('rssi', 'Unknown')} dBm")
            if device.get('manufacturer_data'):
                logger.info(f"    Manufacturer: {device['manufacturer_data']}")
            if device.get('service_uuids'):
                logger.info(f"    Services: {', '.join(device['service_uuids'][:3])}...")

    logger.info(f"\nThreats detected: {len(transport.threats)}")

    if transport.threats:
        logger.info("\nDetected Threats:")
        for i, threat in enumerate(transport.threats, 1):
            logger.info(f"\n  Threat {i}:")
            logger.info(f"    Type: {threat['threat_type']}")
            logger.info(f"    Device: {threat.get('device_name', 'Unknown')} ({threat.get('mac_address', 'Unknown')})")
            logger.info(f"    Severity: {threat['severity']}")
            logger.info(f"    Rules: {', '.join([r['name'] for r in threat.get('matched_rules', [])])}")

    # Behavioral stats
    logger.info("\nBehavioral Metrics:")
    logger.info(f"  Devices with name changes: {len([m for m in detector.device_name_changes.values() if m])}")
    logger.info(f"  Devices with manufacturer changes: {len([m for m in detector.device_manufacturer_changes.values() if m])}")

    high_appearance_rate = [
        mac for mac in detector.device_history.keys()
        if detector._calculate_appearance_rate(mac) > 10
    ]
    if high_appearance_rate:
        logger.info(f"  Devices with high appearance rate: {len(high_appearance_rate)}")

    logger.info("\n" + "=" * 80)
    logger.info("Test complete")
    logger.info("=" * 80)


if __name__ == '__main__':
    try:
        asyncio.run(test_ble_detector())
    except KeyboardInterrupt:
        logger.info("\nTest interrupted by user")
    except Exception as e:
        logger.error(f"Test failed: {e}", exc_info=True)
        sys.exit(1)
