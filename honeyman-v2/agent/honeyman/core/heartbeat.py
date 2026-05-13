#!/usr/bin/env python3
"""
Heartbeat service.

Periodically POSTs sensor health + current location to:
    POST /api/v2/sensors/{sensor_id}/heartbeat

Payload matches the backend's SensorHeartbeat schema
(see dashboard-v2/backend/app/schemas/sensor.py):

    {
        "sensor_id":          "<id>",
        "timestamp":          "<isoformat utc>",
        "is_online":          true,
        "enabled_detectors":  ["usb", "wifi"],
        "system_info":        { "cpu_percent": ..., "uptime_seconds": ... },
        "location":           { "latitude": ..., "longitude": ..., "method": "gps" }
    }

Including 'location' on the heartbeat is what lets idle sensors with no
recent threats still show up on the map at the right place.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime

import psutil

logger = logging.getLogger(__name__)


class HeartbeatService:
    def __init__(self, agent, transport, interval=60):
        self.agent = agent
        self.transport = transport
        self.interval = interval
        self.running = False
        self.task = None

    async def start(self):
        if self.running:
            return
        self.running = True
        self.task = asyncio.create_task(self._heartbeat_loop())
        logger.info("Heartbeat service started (interval=%ss)", self.interval)

    async def stop(self):
        self.running = False
        if self.task is not None:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info("Heartbeat service stopped")

    async def _heartbeat_loop(self):
        while self.running:
            try:
                payload = await self._collect_heartbeat_data()
                await self.transport.send(payload, topic="heartbeat")
                logger.debug("Sent heartbeat")
            except Exception as exc:
                logger.error("Error sending heartbeat: %s", exc)
            await asyncio.sleep(self.interval)

    async def _collect_heartbeat_data(self):
        agent_status = self.agent.get_status()
        enabled_detectors = [
            name
            for name, info in agent_status.get("detectors", {}).items()
            if isinstance(info, dict) and info.get("running")
        ]

        payload = {
            "sensor_id": self.agent.config.get("sensor_id"),
            "timestamp": datetime.utcnow().isoformat(),
            "is_online": bool(self.agent.running),
            "enabled_detectors": enabled_detectors,
            "system_info": {
                "cpu_percent": psutil.cpu_percent(interval=None),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage("/").percent,
                "uptime_seconds": self._get_uptime(),
                "agent_version": "2.0.0",
            },
        }

        location = await self._get_location()
        if location:
            payload["location"] = location

        return payload

    async def _get_location(self):
        location_service = getattr(self.agent, "location_service", None)
        if location_service is None:
            return None
        try:
            loc = await location_service.get_location()
        except Exception as exc:
            logger.debug("Heartbeat location fetch failed: %s", exc)
            return None
        if not loc:
            return None
        out = {}
        if loc.get("lat") is not None:
            out["latitude"] = loc["lat"]
        if loc.get("lon") is not None:
            out["longitude"] = loc["lon"]
        if loc.get("source"):
            out["method"] = loc["source"]
        if loc.get("accuracy") is not None:
            out["accuracy"] = loc["accuracy"]
        if loc.get("city"):
            out["city"] = loc["city"]
        if loc.get("country"):
            out["country"] = loc["country"]
        return out or None

    @staticmethod
    def _get_uptime():
        try:
            with open("/proc/uptime", "r") as f:
                return float(f.readline().split()[0])
        except (OSError, ValueError):
            return 0.0
