"""Test fixtures for backend integration tests.

Runs against a real Postgres + Redis — in CI those are GitHub Actions
service containers; locally, point DATABASE_URL and REDIS_URL at
whatever you have running.

We do NOT use FastAPI's lifespan in these tests, which means the MQTT
subscriber and the WebSocket Redis subscriber stay dormant. Threats
POST publishes to Redis through a try/except that swallows the
"redis client not connected" AttributeError, so the test client still
gets a 201 — we're testing the HTTP surface, not the WS broadcast.

Rate limiting is force-disabled here. /sensors/register caps at
10/hour/IP; the smoke flow registers more sensors than that in seconds.
"""

from __future__ import annotations

import os

# Must be set BEFORE any `app.*` import — backend modules read these at
# import time (settings, async_engine, rate_limit module).
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://honeyman:honeyman@localhost:5432/honeyman_test",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
# pydantic-settings 2.1 eager-json-decodes List[str] env vars before the
# field_validator runs; the CSV form fails here. Use JSON-array form.
os.environ.setdefault("CORS_ORIGINS", '["http://localhost:3000"]')

from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


def _sync_db_url() -> str:
    """psycopg2-flavored URL for the synchronous bootstrap below."""
    return os.environ["DATABASE_URL"].replace("+asyncpg", "")


@pytest.fixture(scope="session", autouse=True)
def _ensure_schema():
    """
    Bring the test DB to head once per session, synchronously.

    Doing this sync side-steps the pytest-asyncio 0.21 limitation where
    session-scoped async fixtures fight the per-test event loop. Alembic
    itself is sync — we run it directly with a psycopg2 URL.

    Also drops any leftover schema before upgrading so a previously
    failed run doesn't leave us with a half-applied state.
    """
    import psycopg2
    from alembic import command
    from alembic.config import Config

    conn = psycopg2.connect(_sync_db_url())
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS threats CASCADE")
        cur.execute("DROP TABLE IF EXISTS sensors CASCADE")
        cur.execute("DROP TABLE IF EXISTS alembic_version CASCADE")
        cur.execute("DROP MATERIALIZED VIEW IF EXISTS threat_stats_hourly CASCADE")
    conn.close()

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", _sync_db_url())
    command.upgrade(cfg, "head")
    yield


@pytest_asyncio.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    """ASGI test client. No lifespan — startup events do not run."""
    # Wipe per-test state. Synchronous psycopg2 keeps this off the
    # async pool so we don't fight ourselves on a connection.
    import psycopg2

    conn = psycopg2.connect(_sync_db_url())
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("DELETE FROM threats")
        cur.execute("DELETE FROM sensors")
    conn.close()

    from app.main import app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def register_sensor(client: AsyncClient, requested_name: str = "ci-sensor") -> tuple[str, str]:
    """Register a sensor; return (sensor_id, api_key). Used by most tests."""
    resp = await client.post(
        "/api/v2/sensors/register",
        json={
            "requested_name": requested_name,
            "capabilities": {"usb": True, "ble": True},
            "enabled_detectors": ["usb", "ble"],
            "platform": "ci",
            "agent_version": "test",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    return body["sensor_id"], body["api_key"]
