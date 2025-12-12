#!/usr/bin/env python3
"""
Protocol Handler - Multi-protocol abstraction layer

Supports:
- MQTT (primary)
- HTTP/REST (fallback)
- WebSocket (future)
- Automatic failover
- Offline queueing
"""

import asyncio
import logging
from collections import deque
from typing import Dict, Any, Optional

from .mqtt_client import MQTTClient
from .http_client import HTTPClient

logger = logging.getLogger(__name__)


class ProtocolHandler:
    """
    Multi-protocol transport handler with automatic failover
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize protocol handler

        Args:
            config: Transport configuration
        """
        self.config = config
        self.primary_protocol = config.get('protocol', 'mqtt')
        self.fallback_protocol = config.get('fallback', 'http')

        # Initialize clients
        self.clients = {}

        if 'mqtt' in [self.primary_protocol, self.fallback_protocol]:
            mqtt_config = config.get('mqtt', {})
            self.clients['mqtt'] = MQTTClient(mqtt_config)

        if 'http' in [self.primary_protocol, self.fallback_protocol]:
            http_config = config.get('http', {})
            self.clients['http'] = HTTPClient(http_config)

        self.active_client = None
        self.queue = deque(maxlen=10000)  # Offline queue
        self.connected = False

    async def connect(self):
        """Establish connection using primary protocol"""
        try:
            primary_client = self.clients.get(self.primary_protocol)
            if primary_client:
                await primary_client.connect()
                self.active_client = primary_client
                self.connected = True
                logger.info(f"Connected via {self.primary_protocol}")
                return True
        except Exception as e:
            logger.error(f"Primary protocol ({self.primary_protocol}) failed: {e}")
            return await self._try_fallback_connect()

    async def _try_fallback_connect(self) -> bool:
        """Try fallback protocol"""
        try:
            fallback_client = self.clients.get(self.fallback_protocol)
            if fallback_client:
                await fallback_client.connect()
                self.active_client = fallback_client
                self.connected = True
                logger.warning(f"Using fallback protocol: {self.fallback_protocol}")
                return True
        except Exception as e:
            logger.error(f"Fallback protocol ({self.fallback_protocol}) failed: {e}")

        self.connected = False
        return False

    async def send(self, data: Dict[str, Any], topic: str = 'threats') -> bool:
        """
        Send data with automatic fallback

        Args:
            data: Data dictionary to send
            topic: Topic/endpoint for message

        Returns:
            True if sent successfully, False otherwise
        """
        if not self.active_client:
            logger.warning("No active connection, queueing message")
            self.queue.append((data, topic))
            return False

        try:
            success = await self.active_client.send(data, topic)

            if success:
                # Flush queue if we have pending messages
                await self._flush_queue()
                return True
            else:
                raise Exception("Send failed")

        except Exception as e:
            logger.error(f"Send failed on {self.active_client.__class__.__name__}: {e}")

            # Try fallback
            if await self._try_fallback(data, topic):
                return True

            # Queue for later
            self.queue.append((data, topic))
            logger.info(f"Message queued ({len(self.queue)} pending)")
            return False

    async def _try_fallback(self, data: Dict[str, Any], topic: str) -> bool:
        """
        Attempt to send via fallback protocol

        Args:
            data: Data to send
            topic: Topic/endpoint

        Returns:
            True if sent successfully
        """
        fallback_client = self.clients.get(self.fallback_protocol)

        if not fallback_client:
            return False

        try:
            success = await fallback_client.send(data, topic)
            if success:
                logger.warning(f"Sent via fallback protocol: {self.fallback_protocol}")
                self.active_client = fallback_client
                return True
        except Exception as e:
            logger.error(f"Fallback send failed: {e}")

        return False

    async def _flush_queue(self):
        """Flush offline queue"""
        if not self.queue:
            return

        logger.info(f"Flushing {len(self.queue)} queued messages...")

        flushed = 0
        failed = []

        while self.queue:
            data, topic = self.queue.popleft()

            try:
                success = await self.active_client.send(data, topic)
                if success:
                    flushed += 1
                else:
                    failed.append((data, topic))
            except Exception as e:
                logger.error(f"Error flushing message: {e}")
                failed.append((data, topic))

        # Re-queue failed messages
        for item in failed:
            self.queue.append(item)

        logger.info(f"Flushed {flushed} messages, {len(failed)} failed")

    async def disconnect(self):
        """Disconnect all clients"""
        for name, client in self.clients.items():
            try:
                await client.disconnect()
                logger.info(f"Disconnected {name} client")
            except Exception as e:
                logger.error(f"Error disconnecting {name} client: {e}")

        self.connected = False
        self.active_client = None

    def get_status(self) -> Dict[str, Any]:
        """Get transport status"""
        return {
            'connected': self.connected,
            'active_protocol': self.active_client.__class__.__name__ if self.active_client else None,
            'queue_size': len(self.queue),
            'primary': self.primary_protocol,
            'fallback': self.fallback_protocol
        }
