#!/usr/bin/env python3
"""
Rule file watcher.

Watches the rules directory for any change to a .yaml / .yml file
(create / modify / delete / move) and calls the rule engine's
reload_rules() method after a short debounce. This is what makes
"edit a YAML on the sensor and the change takes effect immediately"
actually true — historically the docs claimed it but no watcher was
ever wired up.

Design notes:
- We use the `watchdog` library because it's pure-Python, packaged,
  and works the same way on Linux / macOS / Windows. inotify is the
  Linux backend; on other platforms it falls back transparently.
- The Observer runs in its own thread; we marshal callbacks back to
  the agent's asyncio loop via call_soon_threadsafe.
- We debounce by `debounce_seconds` so an editor that writes-and-
  rename-saves doesn't trigger five reloads in a row.
- If watchdog isn't installed (older sensors, dev hosts without the
  optional dep), the service logs a warning and becomes a no-op
  rather than crashing the agent. The agent still works; rule edits
  just need a manual restart, same as before.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_DEBOUNCE_SECONDS = 1.0


class RuleWatcherService:
    """Watch a rules directory and trigger reload_rules() on YAML changes."""

    def __init__(
        self,
        rules_dir: str | Path,
        rule_engine,
        debounce_seconds: float = DEFAULT_DEBOUNCE_SECONDS,
    ):
        self.rules_dir = Path(rules_dir)
        self.rule_engine = rule_engine
        self.debounce_seconds = debounce_seconds

        self._observer = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._pending: Optional[asyncio.TimerHandle] = None
        self._available = True

        try:
            # Lazy import so the agent runs even if watchdog isn't
            # installed yet (sensors that pre-date this commit).
            from watchdog.observers import Observer  # noqa: F401
            from watchdog.events import FileSystemEventHandler  # noqa: F401
        except ImportError:
            self._available = False
            logger.warning(
                "watchdog not installed — rule hot-reload disabled. "
                "Run `pip install watchdog` (or reinstall the agent) "
                "to enable; until then, restart the agent after editing rules."
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        if not self._available:
            return
        if self._observer is not None:
            return
        if not self.rules_dir.exists():
            logger.warning(
                "Rule watcher: rules_dir %s does not exist — not starting watcher",
                self.rules_dir,
            )
            return

        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        # Capture the asyncio loop so the watchdog thread can marshal
        # reload callbacks back onto it. The agent calls start() from
        # the loop, so get_running_loop is safe here.
        self._loop = asyncio.get_running_loop()

        watcher = self  # for closure

        class _Handler(FileSystemEventHandler):
            def _maybe_reload(self, path: str) -> None:
                if path.endswith(".yaml") or path.endswith(".yml"):
                    watcher._schedule_reload(path)

            def on_created(self, event):
                if not event.is_directory:
                    self._maybe_reload(event.src_path)

            def on_modified(self, event):
                if not event.is_directory:
                    self._maybe_reload(event.src_path)

            def on_deleted(self, event):
                if not event.is_directory:
                    self._maybe_reload(event.src_path)

            def on_moved(self, event):
                # Both src and dest matter — a YAML renamed in or out
                # of the tree should trigger a reload.
                if not event.is_directory:
                    self._maybe_reload(event.src_path)
                    self._maybe_reload(event.dest_path)

        self._observer = Observer()
        self._observer.schedule(_Handler(), str(self.rules_dir), recursive=True)
        self._observer.start()
        logger.info(
            "Rule watcher started on %s (debounce=%.1fs)",
            self.rules_dir,
            self.debounce_seconds,
        )

    async def stop(self) -> None:
        if self._observer is None:
            return
        try:
            self._observer.stop()
            self._observer.join(timeout=5)
        except Exception as exc:  # pragma: no cover
            logger.warning("Rule watcher stop raised: %s", exc)
        self._observer = None
        if self._pending is not None:
            self._pending.cancel()
            self._pending = None
        logger.info("Rule watcher stopped")

    # ------------------------------------------------------------------
    # Reload plumbing
    # ------------------------------------------------------------------
    def _schedule_reload(self, path: str) -> None:
        """
        Called from the watchdog thread. Hops to the asyncio loop and
        debounces — if more events arrive within debounce_seconds we
        cancel the prior reload and reschedule.
        """
        if self._loop is None or self._loop.is_closed():
            return
        try:
            self._loop.call_soon_threadsafe(self._arm_debounce, path)
        except RuntimeError:
            # Loop is shutting down; drop the event silently.
            return

    def _arm_debounce(self, path: str) -> None:
        if self._pending is not None:
            self._pending.cancel()
        logger.debug("Rule change detected at %s; reload armed", path)
        self._pending = self._loop.call_later(
            self.debounce_seconds, self._do_reload
        )

    def _do_reload(self) -> None:
        self._pending = None
        try:
            self.rule_engine.reload_rules()
        except Exception as exc:
            # Don't let a malformed YAML kill the agent. The rule
            # engine itself logs the parse error.
            logger.warning("reload_rules() raised: %s", exc)

    def get_status(self) -> dict:
        return {
            "available": self._available,
            "running": self._observer is not None and self._observer.is_alive(),
            "rules_dir": str(self.rules_dir),
            "debounce_seconds": self.debounce_seconds,
        }
