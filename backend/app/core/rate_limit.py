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

import logging
from typing import Any, Awaitable, Callable

from fastapi import Request

from .config import settings

logger = logging.getLogger(__name__)


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

    # Use Redis DB 1 to keep counter keys separate from the WS pub/sub
    # channel that lives on DB 0. If the REDIS_URL has its own db suffix,
    # honour it — operators may be deliberately co-locating.
    redis_url = settings.REDIS_URL
    # If the URL has no /N segment, append /1 for the limiter.
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
REGISTER_CAP = "10/hour"                                   # sensor self-register
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
    "DEFAULT_CAP",
    "attach_rate_limit_handler",
]
