#!/usr/bin/env python3
"""HTTPS client — default sensor transport.

Authenticates writes with a per-sensor API key (Bearer token). The key is
loaded from a credentials file (default /etc/honeyman/api_key, mode 0600);
a `transport.https.api_key` field in config takes precedence for testing.

Endpoints:
    POST {base_url}/api/v2/threats                       — threat ingest
    POST {base_url}/api/v2/sensors/{sensor_id}/heartbeat — heartbeat
    POST {base_url}/api/v2/sensors/register              — self-register (no auth)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

import aiohttp

logger = logging.getLogger(__name__)

DEFAULT_API_KEY_FILE = "/etc/honeyman/api_key"


class HTTPClient:
    """HTTPS+API-key client for the dashboard backend."""

    def __init__(self, config: Dict[str, Any]):
        self.base_url: str = config.get("base_url", "https://api.honeymanproject.com").rstrip("/")
        self.api_prefix: str = config.get("api_prefix", "/api/v2")
        self.sensor_id: Optional[str] = config.get("sensor_id")
        self.timeout: float = float(config.get("timeout", 30))
        self.verify_ssl: bool = bool(config.get("verify_ssl", True))

        # API key: explicit config wins, otherwise read from file.
        self.api_key: Optional[str] = config.get("api_key") or self._load_api_key(
            config.get("api_key_file", DEFAULT_API_KEY_FILE)
        )
        if not self.api_key:
            logger.warning(
                "No API key configured. The agent will fail on the first write. "
                "Run install.sh to register, or set transport.https.api_key_file."
            )

        self.session: Optional[aiohttp.ClientSession] = None
        self.connected: bool = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def connect(self) -> bool:
        """Initialise the aiohttp session and ping the public health endpoint."""
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            headers = {
                "User-Agent": "honeyman-agent/2.0",
                "Content-Type": "application/json",
            }
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            self.session = aiohttp.ClientSession(
                timeout=timeout, connector=connector, headers=headers
            )

            # Public health probe — no auth required, lives outside the api prefix.
            try:
                async with self.session.get(f"{self.base_url}/health") as resp:
                    if resp.status == 200:
                        self.connected = True
                        logger.info("HTTPS client connected to %s", self.base_url)
                        return True
                    logger.warning(
                        "Health probe to %s returned %s — connecting anyway",
                        self.base_url,
                        resp.status,
                    )
            except aiohttp.ClientError as exc:
                logger.warning("Health probe failed (%s) — connecting anyway", exc)

            self.connected = True  # Don't gate on health; backend may be reachable for writes only
            return True

        except Exception as exc:
            logger.error("HTTPS client failed to initialise: %s", exc)
            self.connected = False
            return False

    async def disconnect(self) -> None:
        if self.session is not None:
            await self.session.close()
            self.session = None
        self.connected = False
        logger.info("HTTPS client disconnected")

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------
    async def send(self, data: Dict[str, Any], topic: str = "threats") -> bool:
        """
        POST `data` to the appropriate endpoint based on `topic`.

        Returns True on 2xx, False otherwise.
        """
        if self.session is None:
            logger.warning("HTTPS session not initialised; call connect() first")
            return False

        endpoint, payload = self._endpoint_for(topic, data)
        if endpoint is None:
            logger.warning("HTTPS client has no endpoint mapping for topic=%r", topic)
            return False

        try:
            async with self.session.post(endpoint, json=payload) as resp:
                if 200 <= resp.status < 300:
                    logger.debug("POST %s → %s", endpoint, resp.status)
                    return True
                body = await resp.text()
                logger.error(
                    "POST %s failed: %s — %s", endpoint, resp.status, body[:300]
                )
                return False
        except aiohttp.ClientError as exc:
            logger.error("HTTPS POST to %s errored: %s", endpoint, exc)
            return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _endpoint_for(
        self, topic: str, data: Dict[str, Any]
    ) -> tuple[Optional[str], Dict[str, Any]]:
        """Map a topic name to (full URL, payload). Payload may be wrapped/unwrapped."""
        prefix = f"{self.base_url}{self.api_prefix}"

        if topic == "threats":
            return f"{prefix}/threats", data

        if topic == "heartbeat":
            sid = self.sensor_id or data.get("sensor_id")
            if not sid:
                logger.error("Heartbeat send requires sensor_id")
                return None, data
            # Backend's path uses sensor_id; body schema also includes it.
            payload = {**data, "sensor_id": sid}
            return f"{prefix}/sensors/{sid}/heartbeat", payload

        if topic == "registration":
            # Onboarding endpoint — no auth required.
            return f"{prefix}/sensors/register", data

        # Unknown topic: best-effort generic POST under sensors/{id}/{topic}.
        sid = self.sensor_id
        if sid:
            return f"{prefix}/sensors/{sid}/{topic}", data
        return None, data

    @staticmethod
    def _load_api_key(path: str) -> Optional[str]:
        """Read the API key from `path`. Returns None if file is missing/empty."""
        try:
            p = Path(path)
            if not p.is_file():
                return None
            key = p.read_text(encoding="utf-8").strip()
            if not key:
                return None
            return key
        except OSError as exc:
            logger.warning("Could not read API key from %s: %s", path, exc)
            return None

    def get_status(self) -> Dict[str, Any]:
        return {
            "connected": self.connected,
            "base_url": self.base_url,
            "has_api_key": bool(self.api_key),
        }
