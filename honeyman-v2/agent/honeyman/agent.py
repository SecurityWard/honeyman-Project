#!/usr/bin/env python3
"""
Main Honeyman Agent - Orchestrates all detection modules
"""

import sys
import signal
import logging
import asyncio
from pathlib import Path
from typing import Optional

from .core.config_manager import ConfigManager
from .core.plugin_manager import PluginManager
from .core.heartbeat import HeartbeatService
from .core.rule_sync import RuleSyncService
from .transport.protocol_handler import ProtocolHandler
from .rules.rule_engine import RuleEngine
from .services.location_service import LocationService
from .utils.logger import setup_logger

logger = logging.getLogger(__name__)


class HoneymanAgent:
    """
    Main agent orchestrator that manages:
    - Configuration loading
    - Detector plugin lifecycle
    - Rule engine
    - Transport layer
    - Heartbeat / health reporting
    - Central rule sync (Phase C)
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or '/etc/honeyman/config.yaml'
        self.running = False
        self.detectors = {}

        # Initialize components
        self.config = None
        self.plugin_manager = None
        self.rule_engine = None
        self.transport = None
        self.heartbeat = None
        self.rule_sync = None
        self.location_service = None

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, initiating shutdown...")
        # stop() is async; just flip the flag and let the run loop notice
        self.running = False

    async def initialize(self):
        """Initialize all agent components"""
        logger.info("Initializing Honeyman Agent...")

        # Load configuration
        logger.info(f"Loading configuration from {self.config_path}")
        self.config = ConfigManager(self.config_path)

        # Setup logging
        setup_logger(self.config.get('logging', {}))

        # Initialize rule engine
        rules_dir = self.config.get('rules_dir', '/etc/honeyman/rules')
        logger.info(f"Loading detection rules from {rules_dir}")
        self.rule_engine = RuleEngine(rules_dir)

        # Initialize transport layer
        logger.info("Initializing transport layer...")
        transport_config = self.config.get('transport', {})
        self.transport = ProtocolHandler(transport_config)
        await self.transport.connect()

        # Initialize location service
        logger.info("Initializing location service...")
        location_config = self.config.get('location', {})
        self.location_service = LocationService(location_config)

        # Initialize plugin manager
        logger.info("Initializing plugin manager...")
        self.plugin_manager = PluginManager(
            rule_engine=self.rule_engine,
            transport=self.transport,
            config=self.config,
            location_service=self.location_service,
        )

        # Load detector plugins based on configuration
        detector_config = self.config.get('detectors', {})
        for detector_name, enabled in detector_config.items():
            if enabled:
                logger.info(f"Loading detector: {detector_name}")
                detector = self.plugin_manager.load_detector(detector_name)
                if detector:
                    self.detectors[detector_name] = detector
                else:
                    logger.warning(f"Failed to load detector: {detector_name}")

        # Initialize heartbeat service
        logger.info("Starting heartbeat service...")
        heartbeat_interval = self.config.get('heartbeat_interval', 60)
        self.heartbeat = HeartbeatService(
            agent=self,
            transport=self.transport,
            interval=heartbeat_interval,
        )

        # Phase C: central rule-sync poller. Disabled by default;
        # enable via rule_sync.enabled in config.
        rule_sync_config = self.config.get('rule_sync', {}) or {}
        self.rule_sync = RuleSyncService(
            config=rule_sync_config,
            transport_config=self.config.get('transport', {}),
        )

        logger.info(f"Agent initialized with {len(self.detectors)} detectors")

    async def start(self):
        """Start the agent and all detectors"""
        if self.running:
            logger.warning("Agent is already running")
            return

        self.running = True
        logger.info("Starting Honeyman Agent...")

        await self.initialize()

        # Start heartbeat service
        await self.heartbeat.start()

        # Start rule-sync poller (no-op if rule_sync.enabled is false)
        if self.rule_sync:
            await self.rule_sync.start()

        # Start all detectors
        tasks = []
        for name, detector in self.detectors.items():
            logger.info(f"Starting detector: {name}")
            task = asyncio.create_task(detector.start())
            tasks.append(task)

        logger.info("All detectors started successfully")
        logger.info("Honeyman Agent is now monitoring for threats...")

        # Wait for all detector tasks
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Detector tasks cancelled")

    async def stop(self):
        """Stop the agent and all detectors gracefully"""
        if not self.running:
            return

        logger.info("Stopping Honeyman Agent...")
        self.running = False

        # Stop heartbeat service
        if self.heartbeat:
            await self.heartbeat.stop()

        # Stop rule-sync poller
        if self.rule_sync:
            await self.rule_sync.stop()

        # Stop all detectors
        for name, detector in self.detectors.items():
            logger.info(f"Stopping detector: {name}")
            await detector.stop()

        # Disconnect transport
        if self.transport:
            await self.transport.disconnect()

        logger.info("Honeyman Agent stopped")

    def get_status(self) -> dict:
        """Get agent status for health reporting"""
        return {
            'running': self.running,
            'detectors': {
                name: detector.get_status()
                for name, detector in self.detectors.items()
            },
            'transport': self.transport.get_status() if self.transport else {},
            'rule_sync': self.rule_sync.get_status() if self.rule_sync else {},
            'rules_loaded': len(self.rule_engine.rules) if self.rule_engine else 0,
        }


def main():
    """Main entry point for the honeyman-agent command"""
    import argparse

    parser = argparse.ArgumentParser(description='Honeyman Agent - Multi-Vector Threat Detection')
    parser.add_argument(
        '-c', '--config',
        default='/etc/honeyman/config.yaml',
        help='Path to configuration file (default: /etc/honeyman/config.yaml)',
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging',
    )
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 2.0.0',
    )

    args = parser.parse_args()

    # Setup basic logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )

    # Create and run agent
    agent = HoneymanAgent(config_path=args.config)

    try:
        asyncio.run(agent.start())
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
