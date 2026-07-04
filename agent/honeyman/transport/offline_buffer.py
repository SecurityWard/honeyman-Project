#!/usr/bin/env python3
"""
SQLite-backed offline buffer for the transport layer.

Why SQLite and not an in-memory deque:

- Persists across agent restarts. If a sensor crashes mid-burst (or the
  agent is restarted by systemd), buffered events survive.
- Bounded disk usage with a single PRAGMA-driven configuration.
- No external service required. The file lives at /var/lib/honeyman/buffer.db
  by default.

Schema (deliberately tiny):

    outbox(
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        topic       TEXT NOT NULL,
        payload     TEXT NOT NULL,   -- JSON-encoded dict
        created_at  REAL NOT NULL,   -- unix epoch
        attempts    INTEGER NOT NULL DEFAULT 0
    )

Concurrency model: this class is intended to be called from a single
asyncio task (ProtocolHandler). SQLite's own locking handles brief bursts
from multiple loops if that ever changes. All writes are wrapped in
short transactions so a kill at any point leaves the DB in a consistent
state.

Public API:
    OfflineBuffer(path: str, max_rows: int = 10000)
    enqueue(topic: str, payload: dict) -> int
    peek_batch(n: int = 100) -> list[QueuedMessage]
    ack(ids: list[int]) -> int
    bump_attempts(ids: list[int]) -> None
    count() -> int
    close() -> None
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)


@dataclass
class QueuedMessage:
    id: int
    topic: str
    payload: dict
    created_at: float
    attempts: int


class OfflineBuffer:
    """Persistent FIFO buffer for transport sends."""

    DEFAULT_PATH = "/var/lib/honeyman/buffer.db"
    DEFAULT_MAX_ROWS = 10_000

    def __init__(self, path: str | None = None, max_rows: int | None = None):
        self.path = path or self.DEFAULT_PATH
        self.max_rows = max_rows or self.DEFAULT_MAX_ROWS
        self._conn: sqlite3.Connection | None = None
        self._open()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def _open(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
        except OSError as exc:
            logger.warning(
                "Could not create dir for offline buffer at %s: %s", self.path, exc
            )
        # check_same_thread=False so we can be used from asyncio threads/tasks.
        self._conn = sqlite3.connect(
            self.path,
            isolation_level=None,        # autocommit; we use explicit transactions
            check_same_thread=False,
            timeout=5.0,
        )
        cur = self._conn.cursor()
        # WAL is friendlier on flash storage and gives us crash safety.
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA temp_store=MEMORY")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS outbox (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                topic       TEXT    NOT NULL,
                payload     TEXT    NOT NULL,
                created_at  REAL    NOT NULL,
                attempts    INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        # No index on id: it's INTEGER PRIMARY KEY, i.e. an alias for the
        # rowid, so it's already the table's b-tree. A separate index would
        # be a redundant duplicate.
        logger.info(
            "Offline buffer ready at %s (max_rows=%d, depth=%d)",
            self.path,
            self.max_rows,
            self._count_unlocked(cur),
        )

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    # ------------------------------------------------------------------
    # Operations
    # ------------------------------------------------------------------
    def enqueue(self, topic: str, payload: dict) -> int:
        """Append a message; returns its rowid. Trims the queue if over cap."""
        if self._conn is None:
            raise RuntimeError("OfflineBuffer is closed")
        payload_json = json.dumps(payload, separators=(",", ":"), default=str)
        now = time.time()
        cur = self._conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            cur.execute(
                "INSERT INTO outbox (topic, payload, created_at) VALUES (?, ?, ?)",
                (topic, payload_json, now),
            )
            rowid = cur.lastrowid
            self._enforce_cap(cur)
            cur.execute("COMMIT")
        except Exception:
            cur.execute("ROLLBACK")
            raise
        return rowid

    def peek_batch(self, n: int = 100) -> list[QueuedMessage]:
        """Return the oldest n messages without removing them."""
        if self._conn is None:
            return []
        cur = self._conn.cursor()
        rows = cur.execute(
            "SELECT id, topic, payload, created_at, attempts "
            "FROM outbox ORDER BY id ASC LIMIT ?",
            (n,),
        ).fetchall()
        out: list[QueuedMessage] = []
        for rid, topic, payload_json, created_at, attempts in rows:
            try:
                payload = json.loads(payload_json)
            except json.JSONDecodeError as exc:
                logger.warning(
                    "Dropping malformed buffered row id=%d: %s", rid, exc
                )
                self.ack([rid])
                continue
            out.append(
                QueuedMessage(
                    id=rid,
                    topic=topic,
                    payload=payload,
                    created_at=created_at,
                    attempts=attempts,
                )
            )
        return out

    def ack(self, ids: Iterable[int]) -> int:
        """Permanently remove the given message rows (e.g. after successful send)."""
        if self._conn is None:
            return 0
        ids = list(ids)
        if not ids:
            return 0
        cur = self._conn.cursor()
        # Manual placeholder list — IN (?,?,...) is faster than executemany for this.
        placeholders = ",".join(["?"] * len(ids))
        cur.execute(f"DELETE FROM outbox WHERE id IN ({placeholders})", ids)
        return cur.rowcount

    def bump_attempts(self, ids: Iterable[int]) -> None:
        """Increment retry counter on messages that failed to send."""
        if self._conn is None:
            return
        ids = list(ids)
        if not ids:
            return
        cur = self._conn.cursor()
        placeholders = ",".join(["?"] * len(ids))
        cur.execute(
            f"UPDATE outbox SET attempts = attempts + 1 WHERE id IN ({placeholders})",
            ids,
        )

    def count(self) -> int:
        if self._conn is None:
            return 0
        cur = self._conn.cursor()
        return self._count_unlocked(cur)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    @staticmethod
    def _count_unlocked(cur: sqlite3.Cursor) -> int:
        return int(cur.execute("SELECT COUNT(*) FROM outbox").fetchone()[0])

    def _enforce_cap(self, cur: sqlite3.Cursor) -> None:
        """Drop oldest rows if the queue exceeds max_rows."""
        depth = self._count_unlocked(cur)
        if depth <= self.max_rows:
            return
        excess = depth - self.max_rows
        cur.execute(
            "DELETE FROM outbox WHERE id IN ("
            "  SELECT id FROM outbox ORDER BY id ASC LIMIT ?"
            ")",
            (excess,),
        )
        logger.warning(
            "Offline buffer full; dropped %d oldest message(s) (cap=%d)",
            excess,
            self.max_rows,
        )

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------
    def get_status(self) -> dict[str, Any]:
        try:
            depth = self.count()
        except Exception:
            depth = -1
        return {
            "path": self.path,
            "depth": depth,
            "max_rows": self.max_rows,
        }
