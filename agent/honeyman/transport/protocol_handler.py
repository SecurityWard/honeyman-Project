#!/usr/bin/env python3
"""
Transport multiplexer.

Default: HTTPS+API-key. MQTT is opt-in via transport.protocol: mqtt
(or as a fallback). Clients are only constructed when the configuration
actually references them.

Topic semantics:
    'threats'       - POST a detected threat
    'heartbeat'     - POST sensor health + location
    'registration'  - sensor self-register (onboarding only)

Offline queue: SQLite-backed FIFO at the path configured under
transport.offline_buffer_path (default /var/lib/honeyman/buffer.db).
Survives agent restarts. Falls back to an in-memory deque if SQLite init
fails (e.g. in unit tests).
"""

from __future__ import annotations

import logging
from collections import deque

from .http_client import HTTPClient
from .mqtt_client import MQTTClient
from .offline_buffer import OfflineBuffer

logger = logging.getLogger(__name__)

VALID_PROTOCOLS = {"https", "http", "mqtt", "none"}

DEFAULT_BUFFER_PATH = "/var/lib/honeyman/buffer.db"
DEFAULT_BUFFER_MAX_ROWS = 10000
FLUSH_BATCH_SIZE = 100


def _normalise_protocol(name):
    if not name:
        return "none"
    n = name.lower()
    if n in ("http", "https"):
        return "https"
    return n


class ProtocolHandler:
    """Multi-protocol client multiplexer with optional fallback."""

    def __init__(self, config):
        self.config = config
        self.primary_protocol = _normalise_protocol(config.get("protocol", "https"))
        self.fallback_protocol = _normalise_protocol(config.get("fallback"))

        if self.primary_protocol not in VALID_PROTOCOLS:
            logger.warning("Unknown protocol %r, defaulting to https", config.get("protocol"))
            self.primary_protocol = "https"

        self.clients = {}
        for proto in {self.primary_protocol, self.fallback_protocol}:
            if proto == "none":
                continue
            self._init_client(proto)

        if not self.clients:
            logger.warning("ProtocolHandler initialised with no transports configured.")

        self.active_client = None
        self.connected = False

        # Persistent FIFO buffer for outbound messages when the active
        # client cannot reach the backend. Falls back to an in-memory
        # deque if the SQLite file cannot be opened.
        self.buffer: OfflineBuffer | None = None
        self.fallback_queue: deque = deque(maxlen=DEFAULT_BUFFER_MAX_ROWS)
        self._init_buffer()

    # ------------------------------------------------------------------
    # Init
    # ------------------------------------------------------------------
    def _init_client(self, proto):
        if proto == "https":
            https_cfg = self.config.get("https") or self.config.get("http") or {}
            self.clients["https"] = HTTPClient(https_cfg)
        elif proto == "mqtt":
            mqtt_cfg = self.config.get("mqtt") or {}
            if not mqtt_cfg.get("broker"):
                logger.warning(
                    "transport.protocol references mqtt but no broker is configured; "
                    "skipping MQTT init"
                )
                return
            self.clients["mqtt"] = MQTTClient(mqtt_cfg)
        else:
            logger.warning("No client implementation for protocol=%r", proto)

    def _init_buffer(self) -> None:
        path = self.config.get("offline_buffer_path") or DEFAULT_BUFFER_PATH
        max_rows = int(self.config.get("offline_buffer_max_rows") or DEFAULT_BUFFER_MAX_ROWS)
        try:
            self.buffer = OfflineBuffer(path=path, max_rows=max_rows)
            logger.info(
                "Persistent offline buffer enabled at %s (depth=%d)",
                path,
                self.buffer.count(),
            )
        except Exception as exc:
            logger.warning(
                "Could not open SQLite offline buffer at %s (%s); "
                "falling back to in-memory deque",
                path,
                exc,
            )
            self.buffer = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def connect(self) -> bool:
        primary = self.clients.get(self.primary_protocol)
        if primary is not None:
            try:
                if await primary.connect():
                    self.active_client = primary
                    self.connected = True
                    logger.info("Connected via %s", self.primary_protocol)
                    # Drain anything queued from a previous run / outage.
                    await self._flush_queue()
                    return True
            except Exception as exc:
                logger.error("Primary protocol %s connect failed: %s", self.primary_protocol, exc)
        return await self._try_fallback_connect()

    async def _try_fallback_connect(self) -> bool:
        fallback = self.clients.get(self.fallback_protocol)
        if fallback is None:
            self.connected = False
            return False
        try:
            if await fallback.connect():
                self.active_client = fallback
                self.connected = True
                logger.warning("Using fallback transport: %s", self.fallback_protocol)
                await self._flush_queue()
                return True
        except Exception as exc:
            logger.error("Fallback %s connect failed: %s", self.fallback_protocol, exc)
        self.connected = False
        return False

    async def disconnect(self) -> None:
        for name, client in self.clients.items():
            try:
                await client.disconnect()
                logger.info("Disconnected %s client", name)
            except Exception as exc:
                logger.error("Error disconnecting %s client: %s", name, exc)
        self.connected = False
        self.active_client = None
        if self.buffer is not None:
            try:
                self.buffer.close()
            except Exception as exc:
                logger.warning("Error closing offline buffer: %s", exc)

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------
    async def send(self, data, topic="threats") -> bool:
        # No active client yet — go straight to the queue.
        if self.active_client is None:
            self._enqueue(topic, data)
            logger.warning(
                "No active transport; queued message (depth=%d)", self._depth()
            )
            return False

        try:
            ok = await self.active_client.send(data, topic)
        except Exception as exc:
            logger.error(
                "Send failed on %s: %s",
                self.active_client.__class__.__name__,
                exc,
            )
            ok = False

        if ok:
            # Opportunistic flush in case we have a backlog.
            await self._flush_queue()
            return True

        if await self._try_fallback(data, topic):
            return True

        # Last resort: persist for later.
        self._enqueue(topic, data)
        logger.info("Queued message after send failure (depth=%d)", self._depth())
        return False

    async def _try_fallback(self, data, topic) -> bool:
        fallback = self.clients.get(self.fallback_protocol)
        if fallback is None or fallback is self.active_client:
            return False
        try:
            if await fallback.send(data, topic):
                logger.warning(
                    "Sent via fallback %s; switching active client",
                    self.fallback_protocol,
                )
                self.active_client = fallback
                return True
        except Exception as exc:
            logger.error("Fallback send errored: %s", exc)
        return False

    # ------------------------------------------------------------------
    # Queue (buffer + deque)
    # ------------------------------------------------------------------
    def _enqueue(self, topic: str, payload) -> None:
        if self.buffer is not None:
            try:
                self.buffer.enqueue(topic, payload)
                return
            except Exception as exc:
                logger.warning(
                    "SQLite buffer enqueue failed (%s); using in-memory fallback", exc
                )
        self.fallback_queue.append((topic, payload))

    def _depth(self) -> int:
        if self.buffer is not None:
            try:
                return self.buffer.count()
            except Exception:
                pass
        return len(self.fallback_queue)

    async def _flush_queue(self) -> None:
        if self.active_client is None or self._depth() == 0:
            return

        depth = self._depth()
        logger.info("Flushing %d queued messages", depth)
        flushed = 0
        bumped = 0

        if self.buffer is not None:
            # Drain in FIFO order, batch by batch, ack-on-success.
            while True:
                batch = self.buffer.peek_batch(FLUSH_BATCH_SIZE)
                if not batch:
                    break
                acked: list[int] = []
                failed: list[int] = []
                for msg in batch:
                    try:
                        ok = await self.active_client.send(msg.payload, msg.topic)
                    except Exception as exc:
                        logger.error("Error flushing message id=%d: %s", msg.id, exc)
                        ok = False
                    if ok:
                        acked.append(msg.id)
                        flushed += 1
                    else:
                        failed.append(msg.id)
                if acked:
                    self.buffer.ack(acked)
                if failed:
                    self.buffer.bump_attempts(failed)
                    bumped += len(failed)
                    # Stop on first batch with failures so we don't hammer a
                    # broken backend with the rest of the queue.
                    break
        else:
            # In-memory deque drain
            while self.fallback_queue:
                topic, payload = self.fallback_queue.popleft()
                try:
                    ok = await self.active_client.send(payload, topic)
                except Exception as exc:
                    logger.error("Error flushing in-memory message: %s", exc)
                    ok = False
                if ok:
                    flushed += 1
                else:
                    self.fallback_queue.appendleft((topic, payload))
                    bumped += 1
                    break

        logger.info("Flushed %d messages, %d failed/bumped", flushed, bumped)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def get_status(self):
        return {
            "connected": self.connected,
            "active_protocol": (
                self.active_client.__class__.__name__ if self.active_client else None
            ),
            "queue_depth": self._depth(),
            "buffer": self.buffer.get_status() if self.buffer is not None else None,
            "primary": self.primary_protocol,
            "fallback": self.fallback_protocol,
        }
