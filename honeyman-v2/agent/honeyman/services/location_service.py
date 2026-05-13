#!/usr/bin/env python3
"""
Location service.

Resolution order (Phase D):

    1. Operator-pinned manual location
        Read from config: location.manual_latitude / .manual_longitude.
        Skips everything else — used when an operator drops a Pi in a
        physical spot and wants exact coordinates on the map.

    2. GPS (via gpsd)
        Talks to a local gpsd over TCP 2947. Most accurate when a GPS
        receiver is attached. ~10m accuracy under open sky.
        Requires gpsd to be running and the GPS to have a fix.

    3. WiFi positioning (Mozilla Location Service)
        Scans nearby BSSIDs with `iw dev <iface> scan`, sends them to
        MLS. Free, rate-limited. ~30m indoor / ~150m outdoor accuracy.
        Set transport-side `location.wifi_positioning_api_key` to use a
        different provider (e.g. Google Geolocation API with your own key).

    4. IP geolocation (ipapi.co)
        Always works. ~5km accuracy — city level. Fallback only.

Results are cached for 5 minutes so we don't hammer gpsd / MLS / ipapi.
The cache TTL is reset every time get_location() returns a fresh hit.

All methods return a dict with the shape:

    {
        "lat":      <float>,
        "lon":      <float>,
        "accuracy": <float meters>,
        "source":   "manual" | "gps" | "wifi" | "ip",
        "city":     <str, optional>,
        "country":  <str, optional>,
    }
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)

DEFAULT_CACHE_TTL = 300                                # 5 minutes
DEFAULT_GPSD_HOST = "127.0.0.1"
DEFAULT_GPSD_PORT = 2947
DEFAULT_GPSD_TIMEOUT = 5.0
MLS_ENDPOINT = "https://location.services.mozilla.com/v1/geolocate?key=test"
GOOGLE_ENDPOINT = "https://www.googleapis.com/geolocation/v1/geolocate"


class LocationService:
    """Resolve the sensor's current location with graceful fallback."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.enabled = bool(self.config.get("enabled", True))
        self.gps_enabled = bool(self.config.get("gps_enabled", False))
        self.gps_host = self.config.get("gpsd_host", DEFAULT_GPSD_HOST)
        self.gps_port = int(self.config.get("gpsd_port", DEFAULT_GPSD_PORT))
        self.gps_timeout = float(self.config.get("gpsd_timeout", DEFAULT_GPSD_TIMEOUT))

        # Operator override (Phase D). If both lat+lon set, all dynamic
        # sources are skipped — the value is treated as ground truth.
        self.manual_lat = self.config.get("manual_latitude")
        self.manual_lon = self.config.get("manual_longitude")
        self.manual_label = self.config.get("manual_label")
        self.manual_accuracy = float(self.config.get("manual_accuracy", 10.0))

        # WiFi positioning. We honour both legacy `google_geolocation_api_key`
        # and the new `wifi_positioning_api_key`. If neither is set we use
        # MLS' free `?key=test` endpoint.
        self.wifi_api_key = (
            self.config.get("wifi_positioning_api_key")
            or self.config.get("google_geolocation_api_key")
        )
        self.wifi_interface = self.config.get("wifi_interface")  # autodetect if None
        self.wifi_max_aps = int(self.config.get("wifi_max_aps", 12))

        self.cache_ttl = float(self.config.get("cache_ttl_seconds", DEFAULT_CACHE_TTL))

        # Last successful resolution (cached for cache_ttl seconds).
        self._cache: Optional[Dict[str, Any]] = None
        self._cache_at: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def get_location(self) -> Optional[Dict[str, Any]]:
        """Return current location dict, or None if disabled / nothing worked."""
        if not self.enabled:
            return None

        # Manual override is checked on every call (cheap) so toggling it
        # in config has immediate effect after a reload.
        manual = self._get_manual()
        if manual is not None:
            self._store_cache(manual)
            return manual

        # Cache hit?
        now = time.monotonic()
        if self._cache is not None and (now - self._cache_at) < self.cache_ttl:
            return self._cache

        # GPS → WiFi → IP, in order.
        loc = None
        if self.gps_enabled:
            loc = await self._get_gps_location()
        if loc is None:
            loc = await self._get_wifi_location()
        if loc is None:
            loc = await self._get_ip_location()

        if loc is not None:
            self._store_cache(loc)
        return loc

    def get_status(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "manual_pinned": self._get_manual() is not None,
            "gps_enabled": self.gps_enabled,
            "wifi_api_key_set": bool(self.wifi_api_key),
            "cache_age_seconds": (
                round(time.monotonic() - self._cache_at, 1)
                if self._cache is not None else None
            ),
            "last_source": self._cache.get("source") if self._cache else None,
        }

    # ------------------------------------------------------------------
    # Method 1: manual override
    # ------------------------------------------------------------------
    def _get_manual(self) -> Optional[Dict[str, Any]]:
        if self.manual_lat is None or self.manual_lon is None:
            return None
        try:
            lat = float(self.manual_lat)
            lon = float(self.manual_lon)
        except (TypeError, ValueError):
            logger.warning(
                "location.manual_latitude/longitude not numeric, ignoring (%r, %r)",
                self.manual_lat, self.manual_lon,
            )
            return None
        out: Dict[str, Any] = {
            "lat": lat,
            "lon": lon,
            "accuracy": self.manual_accuracy,
            "source": "manual",
        }
        if self.manual_label:
            out["label"] = self.manual_label
        return out

    # ------------------------------------------------------------------
    # Method 2: GPS via gpsd
    # ------------------------------------------------------------------
    async def _get_gps_location(self) -> Optional[Dict[str, Any]]:
        """Talk to gpsd over TCP, return a TPV fix or None."""
        try:
            return await asyncio.wait_for(self._gpsd_fetch(), timeout=self.gps_timeout)
        except asyncio.TimeoutError:
            logger.debug("gpsd timed out after %ss", self.gps_timeout)
            return None
        except Exception as exc:
            logger.debug("gpsd query failed: %s", exc)
            return None

    async def _gpsd_fetch(self) -> Optional[Dict[str, Any]]:
        """Run blocking gpsd protocol in a thread."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._gpsd_blocking)

    def _gpsd_blocking(self) -> Optional[Dict[str, Any]]:
        """
        Synchronous gpsd client. Connects, requests JSON, reads up to
        ~20 lines waiting for a TPV with mode >= 2. Closes cleanly.
        """
        try:
            sock = socket.create_connection(
                (self.gps_host, self.gps_port),
                timeout=self.gps_timeout,
            )
        except OSError as exc:
            logger.debug("Could not connect to gpsd at %s:%s: %s",
                         self.gps_host, self.gps_port, exc)
            return None

        try:
            sock.sendall(b'?WATCH={"enable":true,"json":true};\n')
            buf = b""
            deadline = time.monotonic() + self.gps_timeout
            for _ in range(40):  # max 40 reads
                if time.monotonic() >= deadline:
                    break
                try:
                    sock.settimeout(max(0.1, deadline - time.monotonic()))
                    chunk = sock.recv(4096)
                except (socket.timeout, OSError):
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line.decode("utf-8", errors="replace"))
                    except json.JSONDecodeError:
                        continue
                    if msg.get("class") != "TPV":
                        continue
                    mode = msg.get("mode", 0)
                    lat = msg.get("lat")
                    lon = msg.get("lon")
                    if mode >= 2 and lat is not None and lon is not None:
                        # epx/epy = expected error in metres on each axis;
                        # fall back to 25m if gpsd doesn't tell us.
                        accuracy = max(
                            msg.get("epx") or 0,
                            msg.get("epy") or 0,
                        ) or 25.0
                        return {
                            "lat": float(lat),
                            "lon": float(lon),
                            "accuracy": float(accuracy),
                            "source": "gps",
                        }
            return None
        finally:
            try:
                sock.sendall(b'?WATCH={"enable":false};\n')
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Method 3: WiFi positioning (Mozilla Location Service / Google)
    # ------------------------------------------------------------------
    async def _get_wifi_location(self) -> Optional[Dict[str, Any]]:
        access_points = await self._scan_wifi_networks()
        if not access_points or len(access_points) < 2:
            # MLS / Google both refuse single-AP queries.
            return None

        url, key = self._wifi_endpoint()
        payload = {"wifiAccessPoints": access_points[: self.wifi_max_aps]}
        params = {"key": key} if key else None

        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, params=params, json=payload) as resp:
                    if resp.status != 200:
                        logger.debug(
                            "WiFi positioning %s -> %s", url, resp.status
                        )
                        return None
                    data = await resp.json()
        except aiohttp.ClientError as exc:
            logger.debug("WiFi positioning request failed: %s", exc)
            return None

        loc = data.get("location") or {}
        lat = loc.get("lat")
        lon = loc.get("lng")
        if lat is None or lon is None:
            return None
        return {
            "lat": float(lat),
            "lon": float(lon),
            "accuracy": float(data.get("accuracy", 100.0)),
            "source": "wifi",
        }

    def _wifi_endpoint(self) -> tuple[str, Optional[str]]:
        """Pick MLS-free or Google-with-your-key. Returns (url, key-or-None)."""
        if self.wifi_api_key:
            # Treat user-provided key as a Google Geolocation API key by default.
            # Operators using MLS' production API can put their own MLS key here too;
            # the endpoint signature is compatible.
            return GOOGLE_ENDPOINT, self.wifi_api_key
        # No key — use Mozilla's free `?key=test` endpoint. Rate-limited but free.
        return MLS_ENDPOINT, None

    async def _scan_wifi_networks(self) -> List[Dict[str, Any]]:
        """
        Run `iw dev <iface> scan` (or `iwlist`) and parse BSSIDs + signal strength.

        Returns a list of {macAddress, signalStrength}. Empty list if no
        interface is present, scan fails, or this isn't Linux.
        """
        iface = self.wifi_interface or self._autodetect_iface()
        if not iface:
            return []
        try:
            proc = await asyncio.create_subprocess_exec(
                "iw", "dev", iface, "scan",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        except (FileNotFoundError, asyncio.TimeoutError, OSError) as exc:
            logger.debug("iw scan unavailable (%s); skipping WiFi positioning", exc)
            return []
        if proc.returncode != 0:
            return []
        return self._parse_iw_scan(stdout.decode("utf-8", errors="replace"))

    @staticmethod
    def _autodetect_iface() -> Optional[str]:
        """Pick the first WiFi interface from `iw dev`."""
        try:
            out = subprocess.check_output(
                ["iw", "dev"],
                stderr=subprocess.DEVNULL,
                timeout=2,
            ).decode("utf-8", errors="replace")
        except (FileNotFoundError, subprocess.SubprocessError):
            return None
        m = re.search(r"Interface\s+(\S+)", out)
        return m.group(1) if m else None

    @staticmethod
    def _parse_iw_scan(scan_output: str) -> List[Dict[str, Any]]:
        """Extract (BSSID, signal) pairs from `iw dev … scan` output."""
        results: List[Dict[str, Any]] = []
        current_bssid: Optional[str] = None
        current_signal: Optional[float] = None
        for line in scan_output.splitlines():
            line = line.strip()
            m_bss = re.match(r"BSS\s+([0-9a-fA-F:]{17})", line)
            if m_bss:
                # Commit the previous AP, if any.
                if current_bssid and current_signal is not None:
                    results.append({
                        "macAddress": current_bssid,
                        "signalStrength": current_signal,
                    })
                current_bssid = m_bss.group(1).lower()
                current_signal = None
                continue
            m_sig = re.match(r"signal:\s+(-?\d+(?:\.\d+)?)\s*dBm", line)
            if m_sig:
                try:
                    current_signal = float(m_sig.group(1))
                except ValueError:
                    current_signal = None
        # Final AP
        if current_bssid and current_signal is not None:
            results.append({
                "macAddress": current_bssid,
                "signalStrength": current_signal,
            })
        return results

    # ------------------------------------------------------------------
    # Method 4: IP geolocation
    # ------------------------------------------------------------------
    async def _get_ip_location(self) -> Optional[Dict[str, Any]]:
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get("https://ipapi.co/json/") as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
        except aiohttp.ClientError as exc:
            logger.debug("IP geolocation failed: %s", exc)
            return None

        lat = data.get("latitude")
        lon = data.get("longitude")
        if lat is None or lon is None:
            return None
        return {
            "lat": float(lat),
            "lon": float(lon),
            "accuracy": 5000.0,        # ~5km, typical IP-based precision
            "source": "ip",
            "city": data.get("city"),
            "country": data.get("country_code"),
        }

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------
    def _store_cache(self, loc: Dict[str, Any]) -> None:
        self._cache = loc
        self._cache_at = time.monotonic()
