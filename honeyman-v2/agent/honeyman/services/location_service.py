#!/usr/bin/env python3
"""Location Service - GPS/WiFi/IP geolocation"""

import logging
import aiohttp
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class LocationService:
    """
    Provides current location using multiple methods:
    1. GPS (most accurate)
    2. WiFi positioning (Google Geolocation API)
    3. IP geolocation (fallback)
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize location service

        Args:
            config: Location configuration
        """
        self.config = config
        self.enabled = config.get('enabled', True)
        self.gps_enabled = config.get('gps_enabled', False)
        self.google_api_key = config.get('google_geolocation_api_key')

        self.last_location = None
        self.cache_ttl = 300  # 5 minutes

    async def get_location(self) -> Optional[Dict[str, Any]]:
        """
        Get current location using best available method

        Returns:
            Location dictionary with lat, lon, accuracy, source
        """
        if not self.enabled:
            return None

        # Try GPS first
        if self.gps_enabled:
            location = await self._get_gps_location()
            if location:
                self.last_location = location
                return location

        # Try WiFi positioning
        if self.google_api_key:
            location = await self._get_wifi_location()
            if location:
                self.last_location = location
                return location

        # Fallback to IP geolocation
        location = await self._get_ip_location()
        if location:
            self.last_location = location
            return location

        # Return cached location if available
        return self.last_location

    async def _get_gps_location(self) -> Optional[Dict[str, Any]]:
        """Get location from GPS (placeholder - requires gpsd)"""
        # TODO: Implement GPS support via gpsd
        logger.debug("GPS location not implemented yet")
        return None

    async def _get_wifi_location(self) -> Optional[Dict[str, Any]]:
        """Get location using WiFi access points (Google Geolocation API)"""
        try:
            # Scan for WiFi networks
            wifi_networks = await self._scan_wifi_networks()
            if not wifi_networks:
                return None

            # Call Google Geolocation API
            url = 'https://www.googleapis.com/geolocation/v1/geolocate'
            params = {'key': self.google_api_key}
            payload = {'wifiAccessPoints': wifi_networks}

            async with aiohttp.ClientSession() as session:
                async with session.post(url, params=params, json=payload, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            'lat': data['location']['lat'],
                            'lon': data['location']['lng'],
                            'accuracy': data.get('accuracy', 100),
                            'source': 'wifi'
                        }
        except Exception as e:
            logger.debug(f"WiFi location failed: {e}")

        return None

    async def _scan_wifi_networks(self) -> list:
        """Scan for nearby WiFi access points (placeholder)"""
        # TODO: Implement WiFi scanning
        return []

    async def _get_ip_location(self) -> Optional[Dict[str, Any]]:
        """Get location from IP address"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://ipapi.co/json/', timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            'lat': data['latitude'],
                            'lon': data['longitude'],
                            'accuracy': 5000,  # ~5km for IP geolocation
                            'source': 'ip',
                            'city': data.get('city'),
                            'country': data.get('country_code')
                        }
        except Exception as e:
            logger.debug(f"IP location failed: {e}")

        return None
