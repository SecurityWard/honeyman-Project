#!/usr/bin/env python3
"""
Test script for Network Detector

Tests OpenCanary honeypot integration
"""

import asyncio
import sys
import logging
import json
from pathlib import Path
import aiohttp

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from honeyman.detectors.network_detector import NetworkDetector
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
        logger.info(f"  Source: {data.get('src_host', 'Unknown')}:{data.get('src_port', 'Unknown')}")
        logger.info(f"  Target: :{data.get('dst_port', 'Unknown')}")
        logger.info(f"  Log Type: {data.get('logtype', 'Unknown')}")
        logger.info(f"  Severity: {data['severity']}")
        logger.info(f"  Matched Rules: {[r['name'] for r in data.get('matched_rules', [])]}")
        return True


async def send_test_events(webhook_url: str):
    """Send test OpenCanary events to webhook"""

    test_events = [
        # SSH brute force
        {
            'logtype': 'ssh.login_attempt',
            'node_id': 'test-honeypot',
            'src_host': '192.168.1.100',
            'src_port': 54321,
            'dst_host': '192.168.1.50',
            'dst_port': 22,
            'username': 'admin',
            'password': 'password123'
        },
        # Port scan
        {
            'logtype': 'portscan.portscan',
            'node_id': 'test-honeypot',
            'src_host': '10.0.0.50',
            'src_port': 0,
            'dst_host': '192.168.1.50',
            'dst_port': 0
        },
        # SMB attack
        {
            'logtype': 'smb.request',
            'node_id': 'test-honeypot',
            'src_host': '172.16.0.100',
            'src_port': 49152,
            'dst_host': '192.168.1.50',
            'dst_port': 445,
            'share': 'IPC$'
        },
        # MySQL attack
        {
            'logtype': 'mysql.login_attempt',
            'node_id': 'test-honeypot',
            'src_host': '203.0.113.42',
            'src_port': 55555,
            'dst_host': '192.168.1.50',
            'dst_port': 3306,
            'username': 'root',
            'password': 'toor'
        },
        # VNC attack
        {
            'logtype': 'vnc.login_attempt',
            'node_id': 'test-honeypot',
            'src_host': '198.51.100.10',
            'src_port': 60000,
            'dst_host': '192.168.1.50',
            'dst_port': 5900,
            'password': 'vnc123'
        },
        # Web attack (SQL injection)
        {
            'logtype': 'http.request',
            'node_id': 'test-honeypot',
            'src_host': '192.0.2.50',
            'src_port': 44444,
            'dst_host': '192.168.1.50',
            'dst_port': 80,
            'request_path': '/admin/login.php?user=admin\' OR 1=1--'
        },
        # Telnet (IoT botnet)
        {
            'logtype': 'telnet.login_attempt',
            'node_id': 'test-honeypot',
            'src_host': '198.51.100.99',
            'src_port': 33333,
            'dst_host': '192.168.1.50',
            'dst_port': 23,
            'username': 'admin',
            'password': 'admin'
        },
    ]

    logger.info("\n" + "=" * 80)
    logger.info("Sending test OpenCanary events to webhook...")
    logger.info("=" * 80 + "\n")

    await asyncio.sleep(2)  # Wait for server to start

    async with aiohttp.ClientSession() as session:
        for i, event in enumerate(test_events, 1):
            try:
                logger.info(f"Sending event {i}/{len(test_events)}: {event['logtype']}")

                async with session.post(webhook_url, json=event) as response:
                    if response.status == 200:
                        logger.info("  event sent successfully")
                    else:
                        logger.warning("  event failed: %s", response.status)

                await asyncio.sleep(1)

            except Exception as e:
                logger.error("  error sending event: %s", e)


async def test_network_detector():
    """Test network detector"""

    logger.info("=" * 80)
    logger.info("Network Detector Test (OpenCanary Integration)")
    logger.info("=" * 80)

    # Configuration
    config = {
        'sensor_id': 'test-sensor-001',
        'network': {
            'webhook_port': 8888,
            'webhook_host': '127.0.0.1',
            'log_tail_mode': False,  # Use webhook mode for testing
        },
        'location': {
            'latitude': 37.7749,
            'longitude': -122.4194,
            'method': 'static'
        }
    }

    # Initialize components
    logger.info("\nInitializing components...")

    rules_dir = Path(__file__).parent / 'rules' / 'network'
    rule_loader = RuleLoader(str(rules_dir))
    rule_engine = RuleEngine(rule_loader)

    transport = MockTransport()

    detector = NetworkDetector(config, rule_engine, transport)

    # Initialize detector
    await detector.initialize()

    logger.info(f"\nNetwork detector initialized successfully")
    logger.info(f"Webhook server: http://{config['network']['webhook_host']}:{config['network']['webhook_port']}")

    # Load rules
    rule_count = len(rule_loader.rules)
    logger.info(f"\nLoaded {rule_count} network rules:")
    for rule_id, rule in rule_loader.rules.items():
        logger.info(f"  - {rule.name} (severity: {rule.severity})")

    logger.info("\n" + "=" * 80)
    logger.info("Starting webhook server and sending test events...")
    logger.info("=" * 80 + "\n")

    # Start detector
    detector_task = asyncio.create_task(detector.start())

    # Send test events
    webhook_url = f"http://{config['network']['webhook_host']}:{config['network']['webhook_port']}/opencanary-webhook"
    await send_test_events(webhook_url)

    # Wait a bit for processing
    await asyncio.sleep(3)

    # Stop detector
    await detector.shutdown()
    detector_task.cancel()

    try:
        await detector_task
    except asyncio.CancelledError:
        pass

    # Display results
    logger.info("\n" + "=" * 80)
    logger.info("Test Results")
    logger.info("=" * 80)

    logger.info(f"\nThreats detected: {len(transport.threats)}")

    if transport.threats:
        logger.info("\nDetected Threats:")
        for i, threat in enumerate(transport.threats, 1):
            logger.info(f"\n  Threat {i}:")
            logger.info(f"    Type: {threat['threat_type']}")
            logger.info(f"    Source: {threat.get('src_host', 'Unknown')}")
            logger.info(f"    Log Type: {threat.get('logtype', 'Unknown')}")
            logger.info(f"    Severity: {threat['severity']}")
            logger.info(f"    Rules: {', '.join([r['name'] for r in threat.get('matched_rules', [])])}")

    # Behavioral stats
    logger.info("\nBehavioral Tracking:")
    logger.info(f"  Sources tracked: {len(detector.source_attempts)}")
    logger.info(f"  Port scan tracking: {len(detector.port_connections)} sources")

    logger.info("\n" + "=" * 80)
    logger.info("Test complete")
    logger.info("\nNote: In production, OpenCanary would send events to this webhook")
    logger.info("Configure OpenCanary to POST events to:")
    logger.info(f"  http://<sensor-ip>:8888/opencanary-webhook")
    logger.info("=" * 80)


if __name__ == '__main__':
    try:
        asyncio.run(test_network_detector())
    except KeyboardInterrupt:
        logger.info("\nTest interrupted by user")
    except Exception as e:
        logger.error(f"Test failed: {e}", exc_info=True)
        sys.exit(1)
