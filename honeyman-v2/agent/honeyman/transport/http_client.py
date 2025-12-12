#!/usr/bin/env python3
"""HTTP Client - Fallback transport protocol"""

import json
import logging
import aiohttp
from typing import Dict, Any

logger = logging.getLogger(__name__)


class HTTPClient:
    """
    HTTP/REST client for fallback communication

    Features:
    - HTTPS with TLS verification
    - API key authentication
    - Retry logic
    - Timeout handling
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize HTTP client

        Args:
            config: HTTP configuration
        """
        self.base_url = config.get('base_url', 'https://api.honeyman.com')
        self.api_key = config.get('api_key')
        self.sensor_id = config.get('sensor_id')
        self.timeout = config.get('timeout', 30)
        self.verify_ssl = config.get('verify_ssl', True)

        self.session = None
        self.connected = False

    async def connect(self):
        """Initialize HTTP session"""
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={
                    'User-Agent': 'honeyman-agent/2.0.0',
                    'X-API-Key': self.api_key,
                    'Content-Type': 'application/json'
                }
            )

            # Test connection with health check
            async with self.session.get(f"{self.base_url}/v2/health") as resp:
                if resp.status == 200:
                    self.connected = True
                    logger.info(f"HTTP client connected to {self.base_url}")
                    return True
                else:
                    logger.error(f"HTTP health check failed: {resp.status}")
                    return False

        except Exception as e:
            logger.error(f"HTTP connection error: {e}")
            self.connected = False
            return False

    async def send(self, data: Dict[str, Any], topic: str = 'threats') -> bool:
        """
        Send data via HTTP POST

        Args:
            data: Data dictionary
            topic: Endpoint type ('threats', 'heartbeat', 'registration')

        Returns:
            True if sent successfully
        """
        if not self.session:
            logger.warning("HTTP session not initialized")
            return False

        try:
            # Build endpoint URL
            if topic == 'threats':
                endpoint = f"{self.base_url}/v2/honeypot/data"
                payload = {
                    'type': 'threats',
                    'honeypot_id': self.sensor_id,
                    'data': [data]  # Wrap in array
                }
            elif topic == 'heartbeat':
                endpoint = f"{self.base_url}/v2/sensors/{self.sensor_id}/heartbeat"
                payload = data
            elif topic == 'registration':
                endpoint = f"{self.base_url}/v2/sensors/register"
                payload = data
            else:
                endpoint = f"{self.base_url}/v2/sensors/{self.sensor_id}/{topic}"
                payload = data

            # Send POST request
            async with self.session.post(endpoint, json=payload) as resp:
                if resp.status in (200, 201):
                    logger.debug(f"HTTP POST to {topic} successful")
                    return True
                else:
                    error_text = await resp.text()
                    logger.error(f"HTTP POST failed: {resp.status} - {error_text}")
                    return False

        except aiohttp.ClientError as e:
            logger.error(f"HTTP client error: {e}")
            return False
        except Exception as e:
            logger.error(f"HTTP send error: {e}")
            return False

    async def disconnect(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None
        self.connected = False
        logger.info("HTTP client disconnected")
