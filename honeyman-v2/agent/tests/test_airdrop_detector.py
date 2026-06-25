#!/usr/bin/env python3
"""
Test script for AirDrop Detector

Tests AirDrop threat detection
"""

import asyncio
import sys
import logging
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from honeyman.detectors.airdrop_detector import AirDropDetector
from honeyman.rules.rule_engine import RuleEngine
from honeyman.rules.rule_loader import RuleLoader

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
        logger.info(f"  Service: {data.get('service_name', 'Unknown')}")
        logger.info(f"  Address: {data.get('address', 'Unknown')}:{data.get('port', 'Unknown')}")
        logger.info(f"  Severity: {data['severity']}")
        logger.info(f"  Matched Rules: {[r['name'] for r in data.get('matched_rules', [])]}")
        return True


async def test_airdrop_detector():
    """Test AirDrop detector"""

    logger.info("=" * 80)
    logger.info("AirDrop Detector Test")
    logger.info("=" * 80)

    # Configuration
    config = {
        'sensor_id': 'test-sensor-001',
        'airdrop': {
            'scan_interval': 60.0,
            'scan_timeout': 15,
            'use_avahi': True
        },
        'location': {
            'latitude': 37.7749,
            'longitude': -122.4194,
            'method': 'static'
        }
    }

    # Initialize components
    logger.info("\nInitializing components...")

    rules_dir = Path(__file__).parent / 'rules' / 'airdrop'
    rule_loader = RuleLoader(str(rules_dir))
    rule_engine = RuleEngine(rule_loader)

    transport = MockTransport()

    detector = AirDropDetector(config, rule_engine, transport)

    # Initialize detector
    try:
        await detector.initialize()
    except Exception as e:
        logger.error(f"Failed to initialize AirDrop detector: {e}")

    if not detector.use_avahi:
        logger.warning("\n" + "=" * 80)
        logger.warning("AirDrop detection requires avahi-utils")
        logger.warning("Install with: sudo apt-get install avahi-utils")
        logger.warning("=" * 80)
        logger.info("\nNote: This detector only works on Linux/macOS with Avahi")
        logger.info("For testing, the detector would scan for _airdrop._tcp services")
        return

    logger.info(f"\nAirDrop detector initialized successfully")
    logger.info(f"Scan interval: {detector.scan_interval}s")

    # Load rules
    rule_count = len(rule_loader.rules)
    logger.info(f"\nLoaded {rule_count} AirDrop rules:")
    for rule_id, rule in rule_loader.rules.items():
        logger.info(f"  - {rule.name} (severity: {rule.severity})")

    logger.info("\n" + "=" * 80)
    logger.info("Starting AirDrop scan...")
    logger.info("This will scan for AirDrop services on the local network")
    logger.info("Scanning for 120 seconds (2 scans). Press Ctrl+C to stop early.")
    logger.info("=" * 80 + "\n")

    # Run detector for 120 seconds (2 scan cycles)
    try:
        detector_task = asyncio.create_task(detector.start())

        await asyncio.sleep(120)

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

    logger.info(f"\nServices discovered: {len(detector.known_services)}")

    if detector.known_services:
        logger.info("\nDiscovered Services:")
        for service_key, service in detector.known_services.items():
            logger.info(f"\n  Service: {service.get('service_name', 'Unknown')}")
            logger.info(f"    Address: {service.get('address', 'Unknown')}:{service.get('port', 'Unknown')}")
            logger.info(f"    Interface: {service.get('interface', 'Unknown')}")
            if service.get('txt_records'):
                logger.info(f"    TXT Records: {service['txt_records'][:100]}...")

    logger.info(f"\nThreats detected: {len(transport.threats)}")

    if transport.threats:
        logger.info("\nDetected Threats:")
        for i, threat in enumerate(transport.threats, 1):
            logger.info(f"\n  Threat {i}:")
            logger.info(f"    Type: {threat['threat_type']}")
            logger.info(f"    Service: {threat.get('service_name', 'Unknown')}")
            logger.info(f"    Address: {threat.get('address', 'Unknown')}")
            logger.info(f"    Severity: {threat['severity']}")
            logger.info(f"    Rules: {', '.join([r['name'] for r in threat.get('matched_rules', [])])}")

    # Behavioral stats
    logger.info("\nBehavioral Metrics:")
    logger.info(f"  Services with announcements tracked: {len(detector.service_appearances)}")

    high_announcement_rate = [
        key for key in detector.known_services.keys()
        if detector._calculate_announcement_rate(key) >= 3
    ]
    if high_announcement_rate:
        logger.info(f"  Services with high announcement rate: {len(high_announcement_rate)}")

    logger.info("\n" + "=" * 80)
    logger.info("Test complete")
    logger.info("\nNote: AirDrop services require:")
    logger.info("  - Apple devices nearby with AirDrop enabled")
    logger.info("  - avahi-browse installed (Linux)")
    logger.info("  - dns-sd command (macOS)")
    logger.info("=" * 80)


if __name__ == '__main__':
    try:
        asyncio.run(test_airdrop_detector())
    except KeyboardInterrupt:
        logger.info("\nTest interrupted by user")
    except Exception as e:
        logger.error(f"Test failed: {e}", exc_info=True)
        sys.exit(1)
