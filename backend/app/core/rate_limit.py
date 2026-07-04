"""Per-IP rate limiting via slowapi.

Resolves [Audit F1] (unauthenticated /sensors/register had no rate limit,
allowing trivial DB-pollution attacks) and [Audit F2] (RATE_LIMIT_ENABLED
was declared in settings but never wired anywhere, misleading operators
into believing rate limiting was active).

slowapi attaches a Limiter instance to the FastAPI app; per-endpoint
decorators declare the cap, and a global exception handler converts
RateLimitExceeded into a 429 response.

When `RATE_LIMIT_ENABLED=false` (or this module fails to import slowapi),
`limiter` is a no-op shim so decorators still resolve cleanly and the
endpoints stay reachable.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Awaitable, Callable

from fastapi import Request

from .config import settings

logger = logging.getLogger(__name__)


def sensor_rate_key(request: Request) -> str:
    """Rate-limit key for authenticated ingest.

    Keyed on the sensor's API key (SHA-256, truncated) rather than the
    client IP, so a single looping or buggy sensor can't flood the DB —
    and can't take the cap down for every other sensor sharing its
    egress IP (a whole conference behind one NAT). Falls back to the
    remote address when there's no bearer token.
    """
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
    if token:
        return "sensor:" + hashlib.sha256(token.encode()).hexdigest()[:24]
    from slowapi.util import get_remote_address
    return get_remote_address(request)


class _NullLimiter:
    """Stand-in used when rate limiting is disabled or slowapi is missing.

    Provides the surface the endpoint decorators expect, but every call is a
    pass-through. We don't pretend to enforce anything — that's the whole
    point of toggling it off.
    """

    def limit(self, *_args: Any, **_kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            return fn
        return decorator


def _real_limiter():  # pragma: no cover - exercised at import time
    """Build a slowapi Limiter keyed on remote IP.

    Storage backend matters when the API runs with >1 uvicorn worker (the
    production unit uses 4). In-memory counters are per-process, so a
    "10/hour" cap actually lets through 40/hour with 4 workers — the
    cap is silently 4x what the operator declared. We force a Redis-backed
    storage so the cap means what it says.
    """
    from slowapi import Limiter
    from slowapi.util import get_remote_address

    # If REDIS_URL already names a db (…/0, …/1), honour it — so the
    # default redis://localhost:6379/0 puts the limiter's counters on the
    # same DB as the WS pub/sub channel. That's safe: slowapi namespaces
    # its keys ("LIMITER/…") and pub/sub uses channel names, so they can't
    # collide. Only when the URL has no db segment do we append /1.
    redis_url = settings.REDIS_URL
    if redis_url.rstrip("/").rsplit("/", 1)[-1].isdigit():
        storage_uri = redis_url
    else:
        storage_uri = redis_url.rstrip("/") + "/1"

    return Limiter(
        key_func=get_remote_address,
        storage_uri=storage_uri,
        # Default per-IP minute cap from settings. Per-endpoint decorators
        # can override; nothing else relies on the default today.
        default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE}/minute"],
    )


if settings.RATE_LIMIT_ENABLED:
    try:
        limiter = _real_limiter()
        rate_limiting_active = True
        logger.info(
            "Rate limiting active (default cap %d/min/IP)",
            settings.RATE_LIMIT_PER_MINUTE,
        )
    except ImportError as exc:
        logger.warning(
            "slowapi not installed, rate limiting disabled despite "
            "RATE_LIMIT_ENABLED=true. Install it with: pip install slowapi. (%s)",
            exc,
        )
        limiter = _NullLimiter()
        rate_limiting_active = False
else:
    limiter = _NullLimiter()
    rate_limiting_active = False
    logger.info("Rate limiting disabled (RATE_LIMIT_ENABLED=false)")


# Per-endpoint cap strings. Kept here so each endpoint pulls a named limit
# rather than repeating magic numbers.
REGISTER_CAP = "10/hour"                                   # sensor self-register (per IP)
# Ingest cap, keyed per-sensor (see sensor_rate_key). Generous for real
# use — detections are episodic and the agent already applies a
# per-(rule, target) cooldown — but bounds a runaway sensor that would
# otherwise write to the DB in a tight loop unbounded.
THREATS_CAP = "120/minute"
DEFAULT_CAP = f"{settings.RATE_LIMIT_PER_MINUTE}/minute"   # blanket per-IP


async def attach_rate_limit_handler(app) -> None:
    """Install the slowapi exception handler on the app if active."""
    if not rate_limiting_active:
        return
    from slowapi import _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


__all__ = [
    "limiter",
    "rate_limiting_active",
    "REGISTER_CAP",
    "THREATS_CAP",
    "DEFAULT_CAP",
    "sensor_rate_key",
    "attach_rate_limit_handler",
]
