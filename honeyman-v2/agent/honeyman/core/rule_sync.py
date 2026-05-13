#!/usr/bin/env python3
"""
Central rule sync.

Polls the backend's GET /api/v2/rules every N seconds. When the manifest
version differs from the local cached version, writes new or changed rule
files into the on-disk rules directory. The rule engine's existing
inotify watcher picks the change up and reloads — no restart needed.

Locally-edited rules are preserved: if a marker file with suffix `.local`
exists next to a rule (e.g. usb/badusb_detection.yaml.local), the remote
copy will not overwrite it.

Disabled by default. Operator opts in via config:

    rule_sync:
      enabled:           true
      interval_seconds:  300       # default poll period
      backend_base_url:  null      # falls back to transport.https.base_url
      api_prefix:        /api/v2
      api_key_file:      /etc/honeyman/api_key
      rules_dir:         /etc/honeyman/rules
      state_file:        /var/lib/honeyman/rules_version
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from pathlib import Path
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL = 300                                  # 5 minutes
DEFAULT_API_PREFIX = "/api/v2"
DEFAULT_API_KEY_FILE = "/etc/honeyman/api_key"
DEFAULT_RULES_DIR = "/etc/honeyman/rules"
DEFAULT_STATE_FILE = "/var/lib/honeyman/rules_version"
LOCAL_MARKER_SUFFIX = ".local"


class RuleSyncService:
    """Periodic pull of the central rule manifest into the on-disk rules dir."""

    def __init__(self, config: dict, transport_config: dict | None = None):
        """
        Args:
            config: the `rule_sync` block from agent config.yaml
            transport_config: the `transport` block — used as a fallback
                              source for base_url + api_key_file so we
                              don't make the operator configure them twice.
        """
        self.enabled = bool(config.get("enabled", False))
        self.interval = int(config.get("interval_seconds", DEFAULT_INTERVAL))

        https_cfg = (transport_config or {}).get("https", {}) if transport_config else {}

        self.base_url = (
            config.get("backend_base_url")
            or https_cfg.get("base_url")
            or "https://api.honeyman.io"
        ).rstrip("/")
        self.api_prefix = (
            config.get("api_prefix")
            or https_cfg.get("api_prefix")
            or DEFAULT_API_PREFIX
        )
        self.api_key_file = (
            config.get("api_key_file")
            or https_cfg.get("api_key_file")
            or DEFAULT_API_KEY_FILE
        )
        self.rules_dir = Path(config.get("rules_dir") or DEFAULT_RULES_DIR)
        self.state_file = Path(config.get("state_file") or DEFAULT_STATE_FILE)
        self.verify_ssl = bool(https_cfg.get("verify_ssl", True))
        self.timeout = float(config.get("timeout") or https_cfg.get("timeout") or 30)

        self._task: asyncio.Task | None = None
        self._stop_event: asyncio.Event | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        if not self.enabled:
            logger.info("Rule sync disabled in config — skipping")
            return
        if self._task is not None:
            return
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._loop())
        logger.info(
            "Rule sync started (interval=%ds, dir=%s)", self.interval, self.rules_dir
        )

    async def stop(self) -> None:
        if self._task is None:
            return
        if self._stop_event is not None:
            self._stop_event.set()
        self._task.cancel()
        try:
            await self._task
        except (asyncio.CancelledError, Exception):
            pass
        self._task = None
        logger.info("Rule sync stopped")

    # ------------------------------------------------------------------
    # Loop
    # ------------------------------------------------------------------
    async def _loop(self) -> None:
        # First sync immediately so a freshly-installed sensor doesn't have
        # to wait `interval` seconds to pick up rule changes.
        while True:
            try:
                await self.sync_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("Rule sync iteration failed: %s", exc)
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.interval)
                # If we got here, _stop_event was set.
                return
            except asyncio.TimeoutError:
                continue

    # ------------------------------------------------------------------
    # One iteration
    # ------------------------------------------------------------------
    async def sync_once(self) -> dict[str, Any]:
        """
        Run a single sync iteration. Returns a small status dict for tests
        or operator-side diagnostics.
        """
        api_key = self._read_api_key()
        if not api_key:
            logger.warning(
                "Rule sync: no API key at %s — skipping iteration", self.api_key_file
            )
            return {"status": "no_api_key"}

        local_version = self._read_local_version()
        url = f"{self.base_url}{self.api_prefix}/rules"
        params: dict[str, str] = {}
        if local_version:
            params["since_version"] = local_version

        headers = {"Authorization": f"Bearer {api_key}"}
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            async with session.get(url, params=params, headers=headers) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.warning(
                        "Rule sync GET %s -> %d: %s", url, resp.status, body[:200]
                    )
                    return {"status": "http_error", "code": resp.status}
                manifest = await resp.json()

        remote_version = manifest.get("version")
        rules = manifest.get("rules") or []

        if not rules:
            if remote_version and remote_version != local_version:
                self._write_local_version(remote_version)
            logger.debug("Rule sync: up to date (version=%s)", (remote_version or "")[:12])
            return {"status": "noop", "version": remote_version}

        applied, skipped_local, skipped_same = self._apply_rules(rules)
        if remote_version:
            self._write_local_version(remote_version)

        logger.info(
            "Rule sync: applied=%d, skipped_local=%d, skipped_unchanged=%d, version=%s",
            applied,
            skipped_local,
            skipped_same,
            (remote_version or "")[:12],
        )
        return {
            "status": "applied",
            "version": remote_version,
            "applied": applied,
            "skipped_local": skipped_local,
            "skipped_same": skipped_same,
        }

    # ------------------------------------------------------------------
    # Apply
    # ------------------------------------------------------------------
    def _apply_rules(self, rules: list[dict]) -> tuple[int, int, int]:
        applied = 0
        skipped_local = 0
        skipped_same = 0

        self.rules_dir.mkdir(parents=True, exist_ok=True)

        for rule in rules:
            rel = rule.get("path")
            content = rule.get("content")
            remote_sha = rule.get("sha256")
            if not rel or content is None:
                logger.warning("Rule sync: malformed entry %r", rule)
                continue

            # Defence in depth: refuse path traversal.
            if "/.." in f"/{rel}" or rel.startswith("/"):
                logger.warning("Rule sync: rejecting suspicious path %r", rel)
                continue

            target = self.rules_dir / rel
            marker = target.with_suffix(target.suffix + LOCAL_MARKER_SUFFIX)

            if marker.exists():
                skipped_local += 1
                logger.debug("Rule sync: %s preserved (%s present)", rel, marker.name)
                continue

            existing_sha = self._sha256_file(target) if target.is_file() else None
            if existing_sha and existing_sha == remote_sha:
                skipped_same += 1
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            self._atomic_write(target, content.encode("utf-8"))
            applied += 1
            logger.debug("Rule sync: wrote %s", rel)

        return applied, skipped_local, skipped_same

    # ------------------------------------------------------------------
    # IO helpers
    # ------------------------------------------------------------------
    def _read_api_key(self) -> str | None:
        try:
            return Path(self.api_key_file).read_text(encoding="utf-8").strip() or None
        except OSError:
            return None

    def _read_local_version(self) -> str | None:
        try:
            return self.state_file.read_text(encoding="utf-8").strip() or None
        except OSError:
            return None

    def _write_local_version(self, version: str) -> None:
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            self._atomic_write(self.state_file, version.encode("utf-8"))
        except OSError as exc:
            logger.warning("Could not persist rules version to %s: %s", self.state_file, exc)

    @staticmethod
    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
        except OSError:
            return ""
        return h.hexdigest()

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        """Write to a temp file in the same dir, then os.replace into place."""
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.tmp")
        try:
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass

    def get_status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "interval_seconds": self.interval,
            "rules_dir": str(self.rules_dir),
            "local_version": (self._read_local_version() or "")[:12],
            "running": self._task is not None and not self._task.done(),
        }
