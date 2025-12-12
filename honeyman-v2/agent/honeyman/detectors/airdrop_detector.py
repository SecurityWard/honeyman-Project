"""
AirDrop Detector - Detects AirDrop abuse and proximity attacks

Detects:
- Suspicious AirDrop service names (attack tools, exploits)
- Generic device spoofing
- Rapid service announcements (flooding)
- Unusual port numbers
- TXT record abuse (payloads, scripts)
"""

import asyncio
import logging
import subprocess
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict
from .base_detector import BaseDetector

logger = logging.getLogger(__name__)


class AirDropDetector(BaseDetector):
    """AirDrop threat detector using avahi-browse"""

    def __init__(self, config: Dict[str, Any], rule_engine, transport):
        super().__init__(config, rule_engine, transport, 'airdrop')

        # Configuration
        self.scan_interval = config.get('airdrop', {}).get('scan_interval', 60.0)
        self.scan_timeout = config.get('airdrop', {}).get('scan_timeout', 15)
        self.use_avahi = config.get('airdrop', {}).get('use_avahi', True)

        # Tracking state
        self.known_services: Dict[str, Dict[str, Any]] = {}
        self.service_appearances: Dict[str, List[datetime]] = defaultdict(list)

        # Thresholds
        self.announcement_rate_window = 300  # 5 minutes
        self.announcement_rate_threshold = 3
        self.history_retention = 600  # 10 minutes
        self.last_cleanup = time.time()

    async def initialize(self):
        """Initialize AirDrop detector"""
        logger.info("Initializing AirDrop detector")

        if self.use_avahi:
            # Check if avahi-browse is available
            if not await self._check_avahi():
                logger.warning("avahi-browse not available, AirDrop detection disabled")
                logger.info("Install with: sudo apt-get install avahi-utils")
                self.use_avahi = False

        if self.use_avahi:
            logger.info("Using avahi-browse for AirDrop service discovery")
        else:
            logger.warning("AirDrop detection disabled (avahi-browse not available)")

        logger.info(f"AirDrop detector initialized (scan interval: {self.scan_interval}s)")

    async def detect(self):
        """Main detection loop"""
        if not self.use_avahi:
            logger.warning("AirDrop detection disabled, sleeping...")
            while self.running:
                await asyncio.sleep(60)
            return

        logger.info("Starting AirDrop detection")

        while self.running:
            try:
                # Scan for AirDrop services
                services = await self._scan_airdrop_services()

                logger.debug(f"Found {len(services)} AirDrop services")

                # Process each service
                for service in services:
                    await self._process_airdrop_service(service)

                # Update known services
                self._update_known_services(services)

                # Periodic cleanup
                if time.time() - self.last_cleanup > self.history_retention:
                    self._cleanup_old_data()

                await asyncio.sleep(self.scan_interval)

            except Exception as e:
                logger.error(f"Error in AirDrop detection loop: {e}", exc_info=True)
                await asyncio.sleep(10)

    async def shutdown(self):
        """Cleanup on shutdown"""
        logger.info("Shutting down AirDrop detector")
        self.running = False
        self.known_services.clear()
        self.service_appearances.clear()

    async def _scan_airdrop_services(self) -> List[Dict[str, Any]]:
        """Scan for AirDrop services using avahi-browse"""
        services = []

        try:
            # Run avahi-browse for _airdrop._tcp services
            process = await asyncio.create_subprocess_exec(
                'avahi-browse', '_airdrop._tcp', '-t', '-r',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.scan_timeout
                )

                output = stdout.decode('utf-8', errors='ignore')
                services = self._parse_avahi_output(output)

            except asyncio.TimeoutError:
                logger.warning("AirDrop scan timeout")
                process.kill()
                await process.wait()

        except FileNotFoundError:
            logger.error("avahi-browse not found")
        except Exception as e:
            logger.error(f"AirDrop scan error: {e}")

        return services

    def _parse_avahi_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse avahi-browse output"""
        services = []
        current_service = {}

        for line in output.split('\n'):
            line = line.strip()

            if line.startswith('='):
                # New service entry
                if current_service:
                    services.append(current_service)

                parts = line.split()
                if len(parts) >= 4:
                    current_service = {
                        'interface': parts[1],
                        'protocol': parts[2],
                        'service_name': ' '.join(parts[3:]),
                        'timestamp': datetime.utcnow().isoformat(),
                        'txt_records': [],
                        'address': '',
                        'port': 0,
                        'detector_type': 'airdrop'
                    }

            elif 'address' in line.lower() and '[' in line:
                # Extract address
                try:
                    address = line.split('[')[1].split(']')[0]
                    if current_service:
                        current_service['address'] = address
                except:
                    pass

            elif 'port' in line.lower() and '[' in line:
                # Extract port
                try:
                    port = int(line.split('[')[1].split(']')[0])
                    if current_service:
                        current_service['port'] = port
                except:
                    pass

            elif line.startswith('"') and current_service:
                # TXT record
                txt_record = line.strip('"')
                current_service['txt_records'].append(txt_record)

        # Add the last service
        if current_service:
            services.append(current_service)

        return services

    async def _process_airdrop_service(self, service: Dict[str, Any]):
        """Process an AirDrop service"""
        try:
            service_key = self._get_service_key(service)

            # Track service appearances
            await self._track_service(service, service_key)

            # Add behavioral metrics
            service['service_announcement_rate'] = self._calculate_announcement_rate(service_key)
            service['service_churn'] = len(self.service_appearances[service_key])

            # Join TXT records for pattern matching
            service['txt_records'] = ' '.join(service.get('txt_records', []))

            # Evaluate against rules
            await self.evaluate_event(service)

        except Exception as e:
            logger.error(f"Error processing AirDrop service: {e}")

    async def _track_service(self, service: Dict[str, Any], service_key: str):
        """Track service appearances"""
        now = datetime.utcnow()

        # Track appearance
        self.service_appearances[service_key].append(now)

        # Clean old appearances
        cutoff = now - timedelta(seconds=self.announcement_rate_window)
        self.service_appearances[service_key] = [
            ts for ts in self.service_appearances[service_key]
            if ts > cutoff
        ]

    def _calculate_announcement_rate(self, service_key: str) -> float:
        """Calculate service announcement rate (announcements per window)"""
        if service_key not in self.service_appearances:
            return 0.0

        return len(self.service_appearances[service_key])

    def _get_service_key(self, service: Dict[str, Any]) -> str:
        """Generate unique service key"""
        address = service.get('address', '')
        port = service.get('port', 0)
        name = service.get('service_name', '')

        return f"{address}:{port}:{name}"

    def _update_known_services(self, services: List[Dict[str, Any]]):
        """Update known services registry"""
        for service in services:
            service_key = self._get_service_key(service)
            self.known_services[service_key] = service

    def _cleanup_old_data(self):
        """Clean up old tracking data"""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.history_retention)

        # Clean appearances
        for service_key in list(self.service_appearances.keys()):
            self.service_appearances[service_key] = [
                ts for ts in self.service_appearances[service_key]
                if ts > cutoff
            ]

            if not self.service_appearances[service_key]:
                del self.service_appearances[service_key]

        # Clean known services
        for service_key in list(self.known_services.keys()):
            try:
                last_seen = datetime.fromisoformat(self.known_services[service_key]['timestamp'])
                if last_seen < cutoff:
                    del self.known_services[service_key]
            except:
                pass

        self.last_cleanup = time.time()
        logger.debug("Cleaned up old AirDrop tracking data")

    async def _check_avahi(self) -> bool:
        """Check if avahi-browse is available"""
        try:
            process = await asyncio.create_subprocess_exec(
                'which', 'avahi-browse',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            await process.wait()
            return process.returncode == 0

        except Exception:
            return False

    def _get_rule_category(self) -> str:
        """Return rule category for this detector"""
        return 'airdrop'
