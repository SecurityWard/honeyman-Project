"""
Network Detector - Integrates with OpenCanary honeypot

Detects network-based threats via OpenCanary:
- SSH brute force
- SMB/CIFS attacks (ransomware, lateral movement)
- Database attacks (MySQL, MSSQL, Redis)
- Port scanning
- VNC remote access
- Web attacks (SQLi, path traversal)
- Telnet attacks (IoT botnets)
"""

import asyncio
import logging
import json
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict
from .base_detector import BaseDetector
from aiohttp import web

logger = logging.getLogger(__name__)


class NetworkDetector(BaseDetector):
    """Network threat detector via OpenCanary honeypot integration"""

    def __init__(self, config: Dict[str, Any], rule_engine, transport):
        super().__init__(config, rule_engine, transport, 'network')

        # Configuration
        self.webhook_port = config.get('network', {}).get('webhook_port', 8888)
        self.webhook_host = config.get('network', {}).get('webhook_host', '0.0.0.0')
        self.opencanary_log_path = config.get('network', {}).get('opencanary_log', '/var/log/opencanary/opencanary.log')
        self.log_tail_mode = config.get('network', {}).get('log_tail_mode', False)

        # Behavioral tracking
        self.source_attempts: Dict[str, Dict[str, List[datetime]]] = defaultdict(lambda: defaultdict(list))
        self.port_connections: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        # Thresholds
        self.ssh_attempt_threshold = 3
        self.vnc_attempt_threshold = 2
        self.port_scan_threshold = 5
        self.tracking_window = 300  # 5 minutes

        # Web server
        self.app = None
        self.runner = None
        self.site = None

        # Log tail
        self.log_position = 0

    async def initialize(self):
        """Initialize network detector"""
        logger.info("Initializing network detector (OpenCanary integration)")

        if self.log_tail_mode:
            logger.info(f"Log tail mode: monitoring {self.opencanary_log_path}")
            try:
                # Get current file size to start tailing from end
                import os
                if os.path.exists(self.opencanary_log_path):
                    self.log_position = os.path.getsize(self.opencanary_log_path)
                    logger.info(f"Starting log tail from position {self.log_position}")
            except Exception as e:
                logger.warning(f"Could not initialize log tail: {e}")

        else:
            # Setup webhook server
            self.app = web.Application()
            self.app.router.add_post('/opencanary-webhook', self._handle_webhook)
            self.app.router.add_get('/health', self._health_check)

            logger.info(f"Webhook mode: listening on {self.webhook_host}:{self.webhook_port}")

        logger.info("Network detector initialized")

    async def detect(self):
        """Main detection loop"""
        if self.log_tail_mode:
            await self._detect_via_log_tail()
        else:
            await self._detect_via_webhook()

    async def _detect_via_webhook(self):
        """Run webhook server for OpenCanary events"""
        logger.info(f"Starting OpenCanary webhook server on port {self.webhook_port}")

        try:
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()

            self.site = web.TCPSite(
                self.runner,
                self.webhook_host,
                self.webhook_port
            )

            await self.site.start()

            logger.info(f"✅ OpenCanary webhook server running on http://{self.webhook_host}:{self.webhook_port}")

            # Keep running
            while self.running:
                await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"Webhook server error: {e}", exc_info=True)

    async def _detect_via_log_tail(self):
        """Tail OpenCanary log file for events"""
        logger.info(f"Starting log tail mode on {self.opencanary_log_path}")

        while self.running:
            try:
                with open(self.opencanary_log_path, 'r') as f:
                    # Seek to last position
                    f.seek(self.log_position)

                    # Read new lines
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                event_data = json.loads(line)
                                await self._process_canary_event(event_data)
                            except json.JSONDecodeError:
                                logger.debug(f"Skipping non-JSON line: {line[:100]}")

                    # Update position
                    self.log_position = f.tell()

                await asyncio.sleep(1)

            except FileNotFoundError:
                logger.warning(f"OpenCanary log not found: {self.opencanary_log_path}")
                await asyncio.sleep(10)
            except Exception as e:
                logger.error(f"Log tail error: {e}")
                await asyncio.sleep(5)

    async def shutdown(self):
        """Cleanup on shutdown"""
        logger.info("Shutting down network detector")
        self.running = False

        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()

        self.source_attempts.clear()
        self.port_connections.clear()

    async def _handle_webhook(self, request):
        """Handle incoming OpenCanary webhook"""
        try:
            event_data = await request.json()

            if event_data:
                await self._process_canary_event(event_data)
                return web.json_response({'status': 'success'})
            else:
                return web.json_response(
                    {'status': 'error', 'message': 'No data received'},
                    status=400
                )

        except Exception as e:
            logger.error(f"Webhook handler error: {e}")
            return web.json_response(
                {'status': 'error', 'message': str(e)},
                status=500
            )

    async def _health_check(self, request):
        """Health check endpoint"""
        return web.json_response({
            'status': 'ok',
            'service': 'honeyman-network-detector',
            'version': '2.0'
        })

    async def _process_canary_event(self, event_data: Dict[str, Any]):
        """Process OpenCanary event"""
        try:
            logtype = event_data.get('logtype', 'unknown')
            src_host = event_data.get('src_host', 'unknown')
            src_port = event_data.get('src_port', 0)
            dst_port = event_data.get('dst_port', 0)

            # Track behavioral patterns
            await self._track_behavior(event_data)

            # Add behavioral metrics
            enriched_data = {
                **event_data,
                'timestamp': event_data.get('timestamp', datetime.utcnow().isoformat()),
                'detector_type': 'network',
                'ssh_failed_attempts': len(self.source_attempts[src_host]['ssh']),
                'vnc_attempts': len(self.source_attempts[src_host]['vnc']),
                'port_connection_count': len(self.port_connections[src_host]),
                'port_scan_rate': self._calculate_port_scan_rate(src_host),
            }

            # Evaluate against rules
            await self.evaluate_event(enriched_data)

            logger.info(f"Processed OpenCanary event: {logtype} from {src_host}:{src_port} -> :{dst_port}")

        except Exception as e:
            logger.error(f"Error processing canary event: {e}", exc_info=True)

    async def _track_behavior(self, event_data: Dict[str, Any]):
        """Track behavioral patterns"""
        logtype = event_data.get('logtype', '')
        src_host = event_data.get('src_host', '')
        dst_port = event_data.get('dst_port', 0)
        now = datetime.utcnow()

        # Track SSH attempts
        if 'ssh' in logtype:
            self.source_attempts[src_host]['ssh'].append(now)

        # Track VNC attempts
        if 'vnc' in logtype:
            self.source_attempts[src_host]['vnc'].append(now)

        # Track database attempts
        if any(db in logtype for db in ['mysql', 'mssql', 'redis']):
            self.source_attempts[src_host]['database'].append(now)

        # Track port connections for scan detection
        self.port_connections[src_host].append({
            'port': dst_port,
            'timestamp': now,
            'logtype': logtype
        })

        # Cleanup old data
        self._cleanup_old_tracking(now)

    def _calculate_port_scan_rate(self, src_host: str) -> float:
        """Calculate port scan rate (unique ports per minute)"""
        if src_host not in self.port_connections:
            return 0.0

        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=60)

        recent_connections = [
            conn for conn in self.port_connections[src_host]
            if conn['timestamp'] > cutoff
        ]

        if not recent_connections:
            return 0.0

        unique_ports = len(set(conn['port'] for conn in recent_connections))
        return unique_ports

    def _cleanup_old_tracking(self, current_time: datetime):
        """Clean up old tracking data"""
        cutoff = current_time - timedelta(seconds=self.tracking_window)

        # Cleanup source attempts
        for source in list(self.source_attempts.keys()):
            for attack_type in list(self.source_attempts[source].keys()):
                self.source_attempts[source][attack_type] = [
                    ts for ts in self.source_attempts[source][attack_type]
                    if ts > cutoff
                ]

                if not self.source_attempts[source][attack_type]:
                    del self.source_attempts[source][attack_type]

            if not self.source_attempts[source]:
                del self.source_attempts[source]

        # Cleanup port connections
        for source in list(self.port_connections.keys()):
            self.port_connections[source] = [
                conn for conn in self.port_connections[source]
                if conn['timestamp'] > cutoff
            ]

            if not self.port_connections[source]:
                del self.port_connections[source]

    def _get_rule_category(self) -> str:
        """Return rule category for this detector"""
        return 'network'
