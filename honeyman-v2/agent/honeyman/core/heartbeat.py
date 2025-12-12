#!/usr/bin/env python3
"""Heartbeat Service - Health monitoring and reporting"""

import asyncio
import logging
import psutil
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger(__name__)


class HeartbeatService:
    """Sends periodic heartbeats to dashboard"""

    def __init__(self, agent, transport, interval: int = 60):
        """
        Initialize heartbeat service

        Args:
            agent: HoneymanAgent instance
            transport: Transport handler
            interval: Heartbeat interval in seconds
        """
        self.agent = agent
        self.transport = transport
        self.interval = interval
        self.running = False
        self.task = None

    async def start(self):
        """Start heartbeat service"""
        if self.running:
            return

        self.running = True
        self.task = asyncio.create_task(self._heartbeat_loop())
        logger.info(f"Heartbeat service started (interval: {self.interval}s)")

    async def stop(self):
        """Stop heartbeat service"""
        self.running = False

        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

        logger.info("Heartbeat service stopped")

    async def _heartbeat_loop(self):
        """Main heartbeat loop"""
        while self.running:
            try:
                heartbeat_data = self._collect_heartbeat_data()
                await self.transport.send(heartbeat_data, topic='heartbeat')
                logger.debug("Sent heartbeat")

            except Exception as e:
                logger.error(f"Error sending heartbeat: {e}")

            await asyncio.sleep(self.interval)

    def _collect_heartbeat_data(self) -> Dict[str, Any]:
        """Collect system metrics for heartbeat"""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'online' if self.agent.running else 'offline',
            'metrics': {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
            },
            'detectors': self.agent.get_status()['detectors'],
            'uptime': self._get_uptime()
        }

    def _get_uptime(self) -> float:
        """Get system uptime in seconds"""
        try:
            with open('/proc/uptime', 'r') as f:
                uptime = float(f.readline().split()[0])
            return uptime
        except:
            return 0.0
